/* packet-oampdu.c
 * Routines for Ethernet OAM PDU dissection.
 * IEEE Std 802.3, clause 57
 *
 * Copyright 2002 Steve Housley <steve_housley@3com.com>
 * Copyright 2005 Dominique Bastien <dbastien@accedian.com>
 * Copyright 2014 Philip Rosenberg-Watt <p.rosenberg-watt[at]cablelabs.com.>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <epan/slow_protocol_subtypes.h>
#include <epan/expert.h>

/* General declarations */
void proto_register_oampdu(void);
void proto_reg_handoff_oampdu(void);

static dissector_handle_t oampdu_handle;

#define OUI_CL_0                    0x00
#define OUI_CL_1                    0x10
#define OUI_CL_2                    0x00
#define OUI_SIZE                       3

#define OAMPDU_HEADER_SIZE              3

/* OAMPDU Flag bits */
#define OAMPDU_FLAGS_LINK_FAULT         0x01
#define OAMPDU_FLAGS_DYING_GASP         0x02
#define OAMPDU_FLAGS_CRITICAL_EVENT     0x04
#define OAMPDU_FLAGS_LOCAL_EVAL         0x08
#define OAMPDU_FLAGS_LOCAL_STABLE       0x10
#define OAMPDU_FLAGS_REMOTE_EVAL        0x20
#define OAMPDU_FLAGS_REMOTE_STABLE      0x40

/* OAMPDU Code */
#define OAMPDU_INFORMATION              0x0
#define OAMPDU_EVENT_NOTIFICATION       0x1
#define OAMPDU_VAR_REQUEST              0x2
#define OAMPDU_VAR_RESPONSE             0x3
#define OAMPDU_LOOPBACK_CTRL            0x4
#define OAMPDU_VENDOR_SPECIFIC          0xFE

/* Information Type */
#define OAMPDU_INFO_TYPE_ENDMARKER      0x0
#define OAMPDU_INFO_TYPE_LOCAL          0x1
#define OAMPDU_INFO_TYPE_REMOTE         0x2
#define OAMPDU_INFO_TYPE_ORG            0xFE

/* Size of fields within a OAMPDU Information */
#define OAMPDU_INFO_TYPE_SZ             1
#define OAMPDU_INFO_LENGTH_SZ           1
#define OAMPDU_INFO_VERSION_SZ          1
#define OAMPDU_INFO_REVISION_SZ         2
#define OAMPDU_INFO_STATE_SZ            1
#define OAMPDU_INFO_OAM_CONFIG_SZ       1
#define OAMPDU_INFO_OAMPDU_CONFIG_SZ    2
#define OAMPDU_INFO_OUI_SZ              3
#define OAMPDU_INFO_VENDOR_SPECIFIC_SZ  4

/* OAM configuration bits */

#define OAMPDU_INFO_CONFIG_MODE         0x01
#define OAMPDU_INFO_CONFIG_UNI          0x02
#define OAMPDU_INFO_CONFIG_LPBK         0x04
#define OAMPDU_INFO_CONFIG_EVENT        0x08
#define OAMPDU_INFO_CONFIG_VAR          0x10

/* Event Type */
#define OAMPDU_EVENT_TYPE_END           0x0
#define OAMPDU_EVENT_TYPE_ESPE          0x1
#define OAMPDU_EVENT_TYPE_EFE           0x2
#define OAMPDU_EVENT_TYPE_EFPE          0x3
#define OAMPDU_EVENT_TYPE_EFSSE         0x4
#define OAMPDU_EVENT_TYPE_OSE           0xFE

/* Size of fields within a OAMPDU Event notification */
#define OAMPDU_EVENT_SEQUENCE_SZ        2
#define OAMPDU_EVENT_TYPE_SZ            1
#define OAMPDU_EVENT_LENGTH_SZ          1
#define OAMPDU_EVENT_TIMESTAMP_SZ       2

/* Size of fields within a OAMPDU ESPE: Errored Symbol Period Event TLV */
#define OAMPDU_ESPE_WINDOW_SZ           8
#define OAMPDU_ESPE_THRESHOLD_SZ        8
#define OAMPDU_ESPE_ERRORS_SZ           8
#define OAMPDU_ESPE_ERR_TOTAL_SZ        8
#define OAMPDU_ESPE_TOTAL_SZ            4

/* Size of fields within a OAMPDU EFE: Errored Frame Event TLV */
#define OAMPDU_EFE_WINDOW_SZ            2
#define OAMPDU_EFE_THRESHOLD_SZ         4
#define OAMPDU_EFE_ERRORS_SZ            4
#define OAMPDU_EFE_ERR_TOTAL_SZ         8
#define OAMPDU_EFE_TOTAL_SZ             4

/* Size of fields within a OAMPDU EFPE: Errored Frame Period Event TLV */
#define OAMPDU_EFPE_WINDOW_SZ           4
#define OAMPDU_EFPE_THRESHOLD_SZ        4
#define OAMPDU_EFPE_ERRORS_SZ           4
#define OAMPDU_EFPE_ERR_TOTAL_SZ        8
#define OAMPDU_EFPE_TOTAL_SZ            4

/* Size of fields within a OAMPDU EFSSE: Errored Frame Seconds Summary Event TLV */
#define OAMPDU_EFSSE_WINDOW_SZ          2
#define OAMPDU_EFSSE_THRESHOLD_SZ       2
#define OAMPDU_EFSSE_ERRORS_SZ          2
#define OAMPDU_EFSSE_ERR_TOTAL_SZ       4
#define OAMPDU_EFSSE_TOTAL_SZ           4

/* Variable Branch Type */
#define OAMPDU_VARS_OBJECT              0x3
#define OAMPDU_VARS_PACKAGE             0x4
#define OAMPDU_VARS_BINDING             0x6
#define OAMPDU_VARS_ATTRIBUTE           0x7

/* OAMPDU Loopback Control bits */
#define OAMPDU_LPBK_ENABLE              0x01
#define OAMPDU_LPBK_DISABLE             0x02

/* DPoE Opcodes */
#define DPOE_OPCODE_GET_REQUEST         0x01
#define DPOE_OPCODE_GET_RESPONSE        0x02
#define DPOE_OPCODE_SET_REQUEST         0x03
#define DPOE_OPCODE_SET_RESPONSE        0x04

/* see IEEE802.3, table 57-4 */
static const value_string code_vals[] = {
    { 0    , "Information" },
    { 1    , "Event Notification" },
    { 2    , "Variable Request" },
    { 3    , "Variable Response" },
    { 4    , "Loopback Control"},
    { 0xFE , "Organization Specific" },
    { 0, NULL }
};

/* see IEEE802.3, table 57-6 */
static const value_string info_type_vals[] = {
    { 0    , "End of TLV marker" },
    { 1    , "Local Information TLV" },
    { 2    , "Remote Information TLV" },
    { 0xFE , "Organization Specific Information TLV" },
    { 0, NULL }
};

/* see IEEE802.3, table 57-12 */
static const value_string event_type_vals[] = {
    { 0    , "End of TLV marker" },
    { 1    , "Errored Symbol Period Event" },
    { 2    , "Errored Frame Event" },
    { 3    , "Errored Frame Period Event" },
    { 4    , "Errored Frame Seconds Summary Event" },
    { 0xFE , "Organization Specific Event TLV" },
    { 0, NULL }
};

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-define. Only the
 * managedObjectClass(3) is put in the branch and the leaf is one of the
 * following value:
 */
static const value_string object_vals[] = {
    {  1, "macObjectClass" },
    {  2, "phyObjectClass"},
    {  3, "repeaterObjectClass"},
    {  4, "groupObjectClass"},
    {  5, "repeaterPortObjectClass"},
    {  6, "mauObjectClass"},
    {  7, "autoNegObjectClass"},
    {  8, "macControlObjectClass"},
    {  9, "macControlFunctionObjectClass"},
    { 10, "oAggregator"},
    { 11, "oAggregationPort"},
    { 12, "oAggPortStats"},
    { 13, "oAggPortDebugInformation" },
    { 15, "pseObjectClass"},
    { 17, "midSpanObjectClass"},
    { 18, "midSpanGroupObjectClass"},
    { 19, "ompObjectClass"},
    { 20, "oamObjectClass" },
    { 21, "mpcpObjectClass" },
    { 24, "pafObjectClass" },
    { 25, "pmeObjectClass"},
    { 0, NULL }
};

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * package(4) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string package_vals[] = {
    {  1, "macMandatoryPkg" },
    {  2, "macRecommendedPkg" },
    {  3, "macOptionalPkg" },
    {  4, "macarrayPkg" },
    {  5, "macExcessiveDeferralPkg" },
    {  6, "phyRecommendedPkg" },
    {  7, "phyMultiplePhyPkg" },
    {  8, "phy100MbpsMonitor" },
    {  9, "repeaterPerfMonitorPkg"},
    { 10, "portPerfMonitorPkg"},
    { 11, "portAddrTrackPkg"},
    { 12, "port100MbpsMonitor"},
    { 13, "mauControlPkg"},
    { 14, "mediaLossTrackingPkg"},
    { 15, "broadbandMAUPkg"},
    { 16, "mau100MbpsMonitor"},
    { 17, "macControlRecommendedPkg" },
    { 18, "portBurst"},
    { 19, "pAggregatorMandatory"},
    { 20, "pAggregatorRecommended"},
    { 21, "pAggregatorOptional"},
    { 22, "pAggregationPortMandatory"},
    { 23, "pAggPortStats"},
    { 24, "pAggPortDebugInformation"},

    { 27, "pseRecommendedPkg"},

    { 30, "fecMonitor"},
    { 35, "pcsMonitor"},
    { 37, "oMPError"},
    { 38, "pafAggregation"},
    { 0, NULL }
};

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * nameBinding(6) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string binding_vals[] = {
    { 26, "repeaterPortName"},
    { 0, NULL }
};

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * attribute(7) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string attribute_vals[] = {
    {   1, "aMACID" },
    {   2, "aFramesTransmittedOK" },
    {   3, "aSingleCollisionFrames" },
    {   4, "aMultipleCollisionFrames" },
    {   5, "aFramesReceivedOK" },
    {   6, "aFrameCheckSequenceErrors" },
    {   7, "aAlignmentErrors" },
    {   8, "aOctetsTransmittedOK" },
    {   9, "aFramesWithDeferredXmissions" },
    {  10, "aLateCollisions" },
    {  11, "aFramesAbortedDueToXSColls" },
    {  12, "aFramesLostDueToIntMACXmitError" },
    {  13, "aCarrierSenseErrors" },
    {  14, "aOctetsReceivedOK" },
    {  15, "aFramesLostDueToIntMACRcvError" },
    {  16, "aPromiscuousStatus" },
    {  17, "aReadMulticastAddressList" },
    {  18, "aMulticastFramesXmittedOK" },
    {  19, "aBroadcastFramesXmittedOK" },
    {  20, "aFramesWithExcessiveDeferral" },
    {  21, "aMulticastFramesReceivedOK" },
    {  22, "aBroadcastFramesReceivedOK" },
    {  23, "aInRangeLengthErrors" },
    {  24, "aOutOfRangeLengthField" },
    {  25, "aFrameTooLongErrors" },
    {  26, "aMACEnableStatus" },
    {  27, "aTransmitEnableStatus" },
    {  28, "aMulticastReceiveStatus" },
    {  29, "aReadWriteMACAddress" },
    {  30, "aCollisionFrames" },
    {  31, "aPHYID" },
    {  32, "aPHYType" },
    {  33, "aPHYTypeList" },
    {  34, "aSQETestErrors" },
    {  35, "aSymbolErrorDuringCarrier" },
    {  36, "aMIIDetect" },
    {  37, "aPHYAdminState" },
    {  38, "aRepeaterID" },
    {  39, "aRepeaterType" },
    {  40, "aRepeaterGroupCapacity" },
    {  41, "aGroupMap" },
    {  42, "aRepeaterHealthState" },
    {  43, "aRepeaterHealthText" },
    {  44, "aRepeaterHealthData" },
    {  45, "aTransmitCollisions" }, /* XXX: was: 44 */
    {  46, "aGroupID" },
    {  47, "aGroupPortCapacity" },
    {  48, "aPortMap" },
    {  49, "aPortID" },
    {  50, "aPortAdminState" },
    {  51, "aAutoPartitionState" },
    {  52, "aReadableFrames" },
    {  53, "aReadableOctets" },
    {  54, "aFrameCheckSequenceErrors" },
    {  55, "aAlignmentErrors" },
    {  56, "aFramesTooLong" },
    {  57, "aShortEvents" },
    {  58, "aRunts" },
    {  59, "aCollisions" },
    {  60, "aLateEvents" },
    {  61, "aVeryLongEvents" },
    {  62, "aDataRateMismatches" },
    {  63, "aAutoPartitions" },
    {  64, "aIsolates" },
    {  65, "aSymbolErrorDuringPacket" },
    {  66, "aLastSourceAddress" },
    {  67, "aSourceAddressChanges" },
    {  68, "aMAUID" },
    {  69, "aMAUType" },
    {  70, "aMAUTypeList" },
    {  71, "aMediaAvailable" },
    {  72, "aLoseMediaCounter" },
    {  73, "aJabber" },
    {  74, "aMAUAdminState" },
    {  75, "aBbMAUXmitRcvSplitType" },
    {  76, "aBroadbandFrequencies" },
    {  77, "aFalseCarriers" },
    {  78, "aAutoNegID" },
    {  79, "aAutoNegAdminState" },
    {  80, "aAutoNegRemoteSignaling" },
    {  81, "aAutoNegAutoConfig" },
    {  82, "aAutoNegLocalTechnologyAbility" },
    {  83, "aAutoNegAdvertisedTechnologyAbility" },
    {  84, "aAutoNegReceivedTechnologyAbility" },
    {  85, "aAutoNegLocalSelectorAbility" },
    {  86, "aAutoNegAdvertisedSelectorAbility" },
    {  87, "aAutoNegReceivedSelectorAbility" },

    {  89, "aMACCapabilities" },
    {  90, "aDuplexStatus" },
    {  91, "aIdleErrorCount"},
    {  92, "aMACControlID" },
    {  93, "aMACControlFunctionsSupported" },
    {  94, "aMACControlFramesTransmitted" },
    {  95, "aMACControlFramesReceived" },
    {  96, "aUnsupportedOpcodesReceived" },
    {  97, "aPAUSELinkDelayAllowance" },
    {  98, "aPAUSEMACCtrlFramesTransmitted" },
    {  99, "aPAUSEMACCtrlFramesReceived" },
    { 100, "aBursts" },
    { 101, "aAggID" },
    { 102, "aAggDescription" },
    { 103, "aAggName" },
    { 104, "aAggActorSystemID" },
    { 105, "aAggActorSystemPriority" },
    { 106, "aAggAggregateOrIndividual" },
    { 107, "aAggActorAdminKey" },
    { 108, "aAggActorOperKey" },
    { 109, "aAggMACAddress" },
    { 110, "aAggPartnerSystemID" },
    { 111, "aAggPartnerSystemPriority" },
    { 112, "aAggPartnerOperKey" },
    { 113, "aAggAdminState" },
    { 114, "aAggOperState" },
    { 115, "aAggTimeOfLastOperChange" },
    { 116, "aAggDataRate" },
    { 117, "aAggOctetsTxOK" },
    { 118, "aAggOctetsRxOK" },
    { 119, "aAggFramesTxOK" },
    { 120, "aAggFramesRxOK" },
    { 121, "aAggMulticastFramesTxOK" },
    { 122, "aAggMulticastFramesRxOK" },
    { 123, "aAggBroadcastFramesTxOK" },
    { 124, "aAggBroadcastFramesRxOK" },
    { 125, "aAggFramesDiscardedOnTx" },
    { 126, "aAggFramesDiscardedOnRx" },
    { 127, "aAggFramesWithTxErrors" },
    { 128, "aAggFramesWithRxErrors" },
    { 129, "aAggUnknownProtocolFrames" },
    { 130, "aAggLinkUpDownNotificationEnable" },
    { 131, "aAggPortList" },
    { 132, "aAggCollectorMaxDelay" },
    { 133, "aAggPortID" },
    { 134, "aAggPortActorSystemPriority" },
    { 135, "aAggPortActorSystemID" },
    { 136, "aAggPortActorAdminKey" },
    { 137, "aAggPortActorOperKey" },
    { 138, "aAggPortPartnerAdminSystemPriority" },
    { 139, "aAggPortPartnerOperSystemPriority" },
    { 140, "aAggPortPartnerAdminSystemID" },
    { 141, "aAggPortPartnerOperSystemID" },
    { 142, "aAggPortPartnerAdminKey" },
    { 143, "aAggPortPartnerOperKey" },
    { 144, "aAggPortSelectedAggID" },
    { 145, "aAggPortAttachedAggID" },
    { 146, "aAggPortActorPort" },
    { 147, "aAggPortActorPortPriority" },
    { 148, "aAggPortPartnerAdminPort" },
    { 149, "aAggPortPartnerOperPort" },
    { 150, "aAggPortPartnerAdminPortPriority" },
    { 151, "aAggPortPartnerOperPortPriority" },
    { 152, "aAggPortActorAdminState" },
    { 153, "aAggPortActorOperState" },
    { 154, "aAggPortPartnerAdminState" },
    { 155, "aAggPortPartnerOperState" },
    { 156, "aAggPortAggregateOrIndividual" },
    { 157, "aAggPortStatsID" },
    { 158, "aAggPortStatsLACPDUsRx" },
    { 159, "aAggPortStatsMarkerPDUsRx" },
    { 160, "aAggPortStatsMarkerResponsePDUsRx" },
    { 161, "aAggPortStatsUnknownRx" },
    { 162, "aAggPortStatsIllegalRx" },
    { 163, "aAggPortStatsLACPDUsTx" },
    { 164, "aAggPortStatsMarkerPDUsTx" },
    { 165, "aAggPortStatsMarkerResponsePDUsTx" },
    { 166, "aAggPortDebugInformationID" },
    { 167, "aAggPortDebugRxState" },
    { 168, "aAggPortDebugLastRxTime" },
    { 169, "aAggPortDebugMuxState" },
    { 170, "aAggPortDebugMuxReason" },
    { 171, "aAggPortDebugActorChurnState" },
    { 172, "aAggPortDebugPartnerChurnState" },
    { 173, "aAggPortDebugActorChurnCount" },
    { 174, "aAggPortDebugPartnerChurnCount" },
    { 175, "aAggPortDebugActorSyncTransitionCount" },
    { 176, "aAggPortDebugPartnerSyncTransitionCount" },
    { 177, "aAggPortDebugActorChangeCount" },
    { 178, "aAggPortDebugPartnerChangeCount" },


    { 236, "aOAMID" },
    { 237, "aOAMAdminState" },
    { 238, "aOAMMode" },
    { 239, "aOAMRemoteMACAddress" },
    { 240, "aOAMRemoteConfiguration" },
    { 241, "aOAMRemotePDUConfiguration" },
    { 242, "aOAMLocalFlagsField" },
    { 243, "aOAMRemoteFlagsField" },
    { 244, "aOAMRemoteRevision" },
    { 245, "aOAMRemoteState" },
    { 246, "aOAMRemoteVendorOUI" },
    { 247, "aOAMRemoteVendorSpecificInfo" },

    { 250, "aOAMUnsupportedCodesRx" },
    { 251, "aOAMInformationTx" },
    { 252, "aOAMInformationRx" },

    { 254, "aOAMUniqueEventNotificationRx" },
    { 255, "aOAMDuplicateEventNotificationRx" },
    { 256, "aOAMLoopbackControlTx" },
    { 257, "aOAMLoopbackControlRx" },
    { 258, "aOAMVariableRequestTx" },
    { 259, "aOAMVariableRequestRx" },
    { 260, "aOAMVariableResponseTx" },
    { 261, "aOAMVariableResponseRx" },
    { 262, "aOAMOrganizationSpecificTx" },
    { 263, "aOAMOrganizationSpecificRx" },
    { 264, "aOAMLocalErrSymPeriodConfig" },
    { 265, "aOAMLocalErrSymPeriodEvent" },
    { 266, "aOAMLocalErrFrameConfig" },
    { 267, "aOAMLocalErrFrameEvent" },
    { 268, "aOAMLocalErrFramePeriodConfig" },
    { 269, "aOAMLocalErrFramePeriodEvent" },
    { 270, "aOAMLocalErrFrameSecsSummaryConfig" },
    { 271, "aOAMLocalErrFrameSecsSummaryEvent" },
    { 272, "aOAMRemoteErrSymPeriodEvent" },
    { 273, "aOAMRemoteErrFrameEvent" },
    { 274, "aOAMRemoteErrFramePeriodEvent" },
    { 275, "aOAMRemoteErrFrameSecsSummaryEvent" },
    { 276, "aFramesLostDueToOAMError" },

    { 333, "aOAMDiscoveryState"},
    { 334, "aOAMLocalConfiguration"},
    { 335, "aOAMLocalPDUConfiguration"},
    { 336, "aOAMLocalRevision"},
    { 337, "aOAMLocalState"},
    { 338, "aOAMUnsupportedCodesTx" },
    { 339, "aOAMUniqueEventNotificationTx" },
    { 340, "aOAMDuplicateEventNotificationTx" },
    { 0, NULL }
};
static value_string_ext attribute_vals_ext = VALUE_STRING_EXT_INIT(attribute_vals);

/*
 * In the OAM protocol the {iso(1) member-body(2) us(840) ieee802dot3(10006)
 * csmacdmgt(30)} prefix for the objects is pre-defined. Only the
 * package(4) is put in the branch and the leaf is one of the
 * following values:
 */
static const value_string indication_vals[] = {
    { 0x01, "Variable Container(s) exceeded OAMPDU data field" },

    { 0x20, "Attribute->Unable to return due to an undetermined error" },
    { 0x21, "Attribute->Unable to return because it is not supported" },
    { 0x22, "Attribute->May have been corrupted due to reset" },
    { 0x23, "Attribute->Unable to return due to a hardware failure" },
    { 0x24, "Attribute->Experience an overflow error" },

    { 0x40, "Object->End of object indication" },
    { 0x41, "Object->Unable to return due to an undetermined error" },
    { 0x42, "Object->Unable to return because it is not supported" },
    { 0x43, "Object->May have been corrupted due to reset" },
    { 0x44, "Object->Unable to return due to a hardware failure" },

    { 0x60, "Package->End of package indication" },
    { 0x61, "Package->Unable to return due to an undetermined error" },
    { 0x62, "Package->Unable to return because it is not supported" },
    { 0x63, "Package->May have been corrupted due to reset" },
    { 0x64, "Package->Unable to return due to a hardware failure" },
    { 0, NULL }
};

static const value_string status_vals[] _U_ = {
    { 0x00, "Unsatisfied, can't complete" },
    { 0x01, "Discovery in process" },
    { 0x02, "Satisfied, Discovery complete" },
    { 0x10, "Satisfied, Discovery complete" },
    { 0x20, "Discovery in process" },
    { 0x40, "Satisfied, Discovery complete" },
    { 0x50, "BUG Satisfied, Discovery complete" },
    { 0x80, "Discovery in process" },

    { 0, NULL }
};

static const value_string branch_vals[] = {
    { 3, "Object" },
    { 4, "Package" },
    { 6, "nameBinding" },
    { 7, "Attribute" },
    { 0, NULL }
};

static const value_string parser_vals[] = {
    { 0, "Forward non-OAMPDUs to higher sublayer" },
    { 1, "Loopback non-OAMPDUs to the lower sublayer" },
    { 2, "Discarding non-OAMPDUs" },
    { 3, "Reserved" },
    { 0, NULL }
};

static const true_false_string mux = {
    "Discard non-OAMPDUs",
    "Forward non-OAMPDUs to lower sublayer"
};

static const true_false_string oam_mode = {
    "DTE configured in Active mode",
    "DTE configured in Passive mode"
};

static const true_false_string oam_uni = {
    "DTE is capable of sending OAMPDUs when rcv path is down",
    "DTE is not capable of sending OAMPDUs when rcv path is down"
};

static const true_false_string oam_lpbk = {
    "DTE is capable of OAM remote loopback mode",
    "DTE is not capable of OAM remote loopback mode"
};

static const true_false_string oam_event = {
    "DTE supports interpreting Link Events",
    "DTE does not support interpreting Link Events"
};

static const true_false_string oam_var = {
    "DTE supports sending Variable Response",
    "DTE does not support sending Variable Response"
};

static const value_string vendor_specific_opcode_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Get Request" },
    { 0x02, "Get Response" },
    { 0x03, "Set Request" },
    { 0x04, "Set Response" },
    { 0x05, "Multicast Request" },
    { 0x06, "Multicast Register" },
    { 0x07, "Multicast Register Response" },
    { 0x08, "Key Exchange" },
    { 0x09, "File Transfer" },
    { 0, NULL }
};

static const value_string dpoe_evt_code_vals[] = {
    { 0x11, "LOS" },
    { 0x12, "Key Exchange Failure" },
    { 0x21, "Port Disable" },
    { 0x41, "Power Failure" },
    { 0x81, "Statistics Alarm" },
    { 0x82, "D-ONU Busy" },
    { 0x83, "MAC Table Overflow" },
    { 0, NULL }
};

/* DPoE Leaf-Branch codes */
#define DPOE_LB_ONU_OBJ                 0xD60000
#define DPOE_LB_NETWORK_PORT_OBJ        0xD60001
#define DPOE_LB_LINK_OBJ                0xD60002
#define DPOE_LB_USER_PORT_OBJ           0xD60003
#define DPOE_LB_QUEUE_OBJ               0xD60004
#define DPOE_LB_MC_LL_OBJ               0xD60006
#define DPOE_LB_ONU_ID                  0xD70002
#define DPOE_LB_FW_INFO                 0xD70003
#define DPOE_LB_CHIPSET_INFO            0xD70004
#define DPOE_LB_DATE_OF_MANUFACTURE     0xD70005
#define DPOE_LB_MFG_INFO                0xD70006
#define DPOE_LB_MAX_LL                  0xD70007
#define DPOE_LB_MAX_NET_PORTS           0xD70008
#define DPOE_LB_NUM_S1_INT              0xD70009
#define DPOE_LB_PKT_BUFFER              0xD7000A
#define DPOE_LB_REP_THRESH              0xD7000B
#define DPOE_LB_LL_FWD_STATE            0xD7000C
#define DPOE_LB_OAM_FR                  0xD7000D
#define DPOE_LB_MFG_ORG_NAME            0xD7000E
#define DPOE_LB_TIME_VARYING_CONTROLS   0xD7000F
#define DPOE_LB_S1_INT_PORT_TYPE        0xD70010
#define DPOE_LB_VENDOR_NAME             0xD70011
#define DPOE_LB_MODEL_NUMBER            0xD70012
#define DPOE_LB_HW_VERSION              0xD70013
#define DPOE_LB_EPON_MODE               0xD70014
#define DPOE_LB_SW_BUNDLE               0xD70015
#define DPOE_LB_S1_INT_PORT_AUTONEG     0xD70105
#define DPOE_LB_PORT_INGRESS_RULE       0xD70501
#define DPOE_LB_QUEUE_CONFIG            0xD7010D
#define DPOE_LB_FW_FILENAME             0xD7010E

/* IEEE 1904.1 SIEPON Leaf-Branch codes used by DPoE */
#define DPOE_LB_1904_1_MAC_ENABLE_STATUS   0x07001A
#define DPOE_LB_1904_1_RW_MAC_ADDRESS      0x07001D
#define DPOE_LB_1904_1_A_PHY_TYPE          0x070020
#define DPOE_LB_1904_1_MEDIA_AVAILABLE     0x070047
#define DPOE_LB_1904_1_AUTONEG_ADM_STATE   0X07004F
#define DPOE_LB_1904_1_DUPLEX_STATUS       0x07005A
#define DPOE_LB_1904_1_MAC_CTl_FUNCTIONS   0x07005D
#define DPOE_LB_1904_1_ONU_PORT_CONFIG     0xD70114
#define DPOE_LB_1904_1_QUEUE_CONFIG        0xD70115
#define DPOE_LB_1904_1_CFG_MCAST_LLID      0xD90107

/* DPoE Object Context */
#define DPOE_OBJ_CTX_ONU                   0x0000
#define DPOE_OBJ_CTX_NETWORK_PORT          0x0001
#define DPOE_OBJ_CTX_UCAST_LOGICAL_LINK    0x0002
#define DPOE_OBJ_CTX_S_INTERFACE           0x0003
#define DPOE_OBJ_CTX_QUEUE                 0x0004
#define DPOE_OBJ_CTX_MEP                   0x0005
#define DPOE_OBJ_CTX_MCAST_LOGICAL_LINK    0x0006
#define DPOE_OBJ_CTX_RESERVED              0x0007

/* As messages get implemented and verified, replace with defined codes from above. */
static const value_string dpoe_variable_descriptor_vals[] = {
    { DPOE_LB_ONU_OBJ,                  "DPoE ONU Object" },
    { DPOE_LB_NETWORK_PORT_OBJ,         "Network Port Object" },
    { DPOE_LB_LINK_OBJ,                 "Link Object" },
    { DPOE_LB_USER_PORT_OBJ,            "User Port Object" },
    { DPOE_LB_QUEUE_OBJ,                "Queue Object" },
    { DPOE_LB_MC_LL_OBJ,                "Multicast Logical Link Object" },
    { 0xD70001,                         "Sequence Number" },
    { DPOE_LB_ONU_ID,                   "DPoE ONU ID" },
    { DPOE_LB_FW_INFO,                  "Firmware Info" },
    { DPOE_LB_CHIPSET_INFO,             "EPON Chip Info" },
    { DPOE_LB_DATE_OF_MANUFACTURE,      "Date of Manufacture" },
    { DPOE_LB_MFG_INFO,                 "Manufacturer Info" },
    { DPOE_LB_MAX_LL,                   "Max Logical Links" },
    { DPOE_LB_MAX_NET_PORTS,            "Number of Network Ports" },
    { DPOE_LB_NUM_S1_INT,               "Number of S1 interfaces" },
    { DPOE_LB_PKT_BUFFER,               "DPoE ONU Packet Buffer" },
    { DPOE_LB_REP_THRESH,               "Report Thresholds" },
    { DPOE_LB_LL_FWD_STATE,             "LLID Forwarding State" },
    { DPOE_LB_OAM_FR,                   "OAM Frame Rate" },
    { DPOE_LB_MFG_ORG_NAME,             "ONU Manufacturer Organization Name" },
    { DPOE_LB_TIME_VARYING_CONTROLS,    "Firmware Mfg Time Varying Controls" },
    { DPOE_LB_S1_INT_PORT_TYPE,         "S1 interface port type" },
    { DPOE_LB_VENDOR_NAME,              "Vendor name" },
    { DPOE_LB_MODEL_NUMBER,             "Model number" },
    { DPOE_LB_HW_VERSION,               "Hardware version" },
    { DPOE_LB_SW_BUNDLE,                "Software bundle" },
    { 0xD90001,                         "Reset DPoE ONU" },
    { 0xD70101,                         "Dynamic Learning Table Size" },
    { 0xD70102,                         "Dynamic Address Age Limit" },
    { 0xD70103,                         "Dynamic MAC Table" },
    { 0xD70104,                         "Static MAC Table" },
    { DPOE_LB_S1_INT_PORT_AUTONEG,      "S1 Interface Port Auto-negotiation" },
    { 0xD70106,                         "Source Address Admission Control" },
    { 0xD70107,                         "MAC Learning Min Guarantee" },
    { 0xD70108,                         "MAC Learning Max Allowed" },
    { 0xD70109,                         "MAC Learning Aggregate Limit" },
    { 0xD7010A,                         "Len Error Discard" },
    { 0xD7010B,                         "Flood Unknown" },
    { 0xD7010C,                         "Local Switching" },
    { DPOE_LB_QUEUE_CONFIG,             "Queue Configuration" },
    { DPOE_LB_FW_FILENAME,              "Firmware Filename" },
    { 0xD70110,                         "Multicast LLID" },
    { 0xD70111,                         "UNI MAC Learned" },
    { 0xD70112,                         "ONU Max Frame Size Capability" },
    { 0xD70113,                         "UNI Max Frame Size Limit" },
    { DPOE_LB_1904_1_ONU_PORT_CONFIG,   "ONU Port Configuration" },
    { DPOE_LB_1904_1_QUEUE_CONFIG,      "Queue Configuration" },
    { 0xD90101,                         "Clear Dynamic MAC Table" },
    { 0xD90102,                         "Add Dynamic MAC Address" },
    { 0xD90103,                         "Delete Dynamic MAC Address" },
    { 0xD90104,                         "Clear Static MAC Table" },
    { 0xD90105,                         "Add Static MAC Table" },
    { 0xD90106,                         "Delete Static MAC Address" },
    { DPOE_LB_1904_1_CFG_MCAST_LLID,    "Config Multicast LLID"},
    { 0xD70201,                         "Rx Unicast Frames" },
    { 0xD70202,                         "Tx Unicast Frames" },
    { 0xD70203,                         "Rx Frame Too Short" },
    { 0xD70204,                         "Rx Frame 64" },
    { 0xD70205,                         "Rx Frame 65_127" },
    { 0xD70206,                         "Rx Frame 128_255" },
    { 0xD70207,                         "Rx Frame 256_511" },
    { 0xD70208,                         "Rx Frame 512_1023" },
    { 0xD70209,                         "Rx Frame 1024_1518" },
    { 0xD7020A,                         "Rx Frame 1519 Plus" },
    { 0xD7020B,                         "Tx Frame 64" },
    { 0xD7020C,                         "Tx Frame 65_127" },
    { 0xD7020D,                         "Tx Frame 128_255" },
    { 0xD7020E,                         "Tx Frame 256_511" },
    { 0xD7020F,                         "Tx Frame 512_1023" },
    { 0xD70210,                         "Tx Frame 1024_1518" },
    { 0xD70211,                         "Tx Frame 1519 Plus" },
    { 0xD70212,                         "Tx Delay Threshold" },
    { 0xD70213,                         "Tx Delay" },
    { 0xD70214,                         "Tx Frames Dropped" },
    { 0xD70215,                         "Tx Bytes Dropped" },
    { 0xD70216,                         "Tx Bytes Delayed" },
    { 0xD70217,                         "Tx Bytes Unused" },
    { 0xD70218,                         "Rx Delay Threshold" },
    { 0xD70219,                         "Rx Delay" },
    { 0xD7021A,                         "Rx Frames Dropped" },
    { 0xD7021B,                         "Rx Bytes Dropped" },
    { 0xD7021C,                         "Rx Bytes Delayed" },
    { 0xD7021D,                         "Optical Mon Temperature" },
    { 0xD7021E,                         "Optical Mon Vcc" },
    { 0xD7021F,                         "Optical Mon Tx Bias Current" },
    { 0xD70220,                         "Optical Mon Tx Power" },
    { 0xD70221,                         "Optical Mon Rx Power" },
    { 0xD70222,                         "Rx Frames Yellow" },
    { 0xD70223,                         "Tx Frames Yellow" },
    { 0xD70224,                         "Tx Bytes Green" },
    { 0xD70225,                         "Rx Bytes Yellow" },
    { 0xD70226,                         "Rx Bytes Green" },
    { 0xD70227,                         "Tx Bytes Yellow" },
    { 0xD70228,                         "Tx Frames Unicast" },
    { 0xD70229,                         "Tx Frames Multicast" },
    { 0xD7022A,                         "Tx Frames Broadcast" },
    { 0xD7022B,                         "Rx Frames Unicast" },
    { 0xD7022C,                         "Rx Frames Multicast" },
    { 0xD7022D,                         "Rx Frames Broadcast" },
    { 0xD7022E,                         "Number of Programmable Counters" },
    { 0xD7022F,                         "L2CP Frames Rx" },
    { 0xD70230,                         "L2CP Octets Rx" },
    { 0xD70231,                         "L2CP Frames Tx" },
    { 0xD70232,                         "L2CP Octets Tx" },
    { 0xD70233,                         "L2CP Frames Discarded" },
    { 0xD70234,                         "L2CP Octets Discarded" },
    { 0xD70235,                         "Tx L2 Errors" },
    { 0xD70236,                         "Rx L2 Errors" },
    { 0xD70237,                         "Frames Over Limit Dropped Uni" },
    { 0xD70238,                         "Octets Over Limit Dropped Uni" },
    { 0xD90201,                         "Clear Status" },
    { 0xD70301,                         "Port Stat Threshold" },
    { 0xD70302,                         "Link Stat Threshold" },
    { 0xD90301,                         "Retrieve Current Alarm Summary" },
    { 0xD70401,                         "Encryption Key Expiry Time" },
    { 0xD70402,                         "Encryption Mode" },
    { DPOE_LB_PORT_INGRESS_RULE,        "Port Ingress Rule" },
    { 0xD70502,                         "Custom Field" },
    { 0xD70503,                         "C-VLAN TPID" },
    { 0xD70504,                         "S-VLAN TPID" },
    { 0xD90501,                         "Clear Port Ingress Rules" },
    { 0xD90502,                         "Add Port Ingress Rule" },
    { 0xD90503,                         "Delete Port Ingress Rule" },
    { 0xD70601,                         "Broadcast Rate Limit" },
    { 0xD70602,                         "Egress Shaping" },
    { 0xD70603,                         "Ingress Policing" },
    { 0xD70604,                         "Queue Rate Control" },
    { 0xD70605,                         "FEC Mode" },
    { 0xD90601,                         "Enable User Traffic" },
    { 0xD90602,                         "Disable User Traffic" },
    { 0xD90603,                         "Loopback Enable" },
    { 0xD90604,                         "Loopback Disable" },
    { 0xD90605,                         "Laser Tx Power Off" },
    { 0x090005,                         "PHY Admin Control" },
    { 0x09000B,                         "Auto Neg Renegotiate" },
    { 0x09000C,                         "Auto Neg Admin Ctrl" },
    { DPOE_LB_1904_1_MAC_ENABLE_STATUS, "MAC Enable Status" },
    { DPOE_LB_1904_1_A_PHY_TYPE,        "PHY Type"},
    { DPOE_LB_1904_1_MEDIA_AVAILABLE,   "Media Available" },
    { DPOE_LB_1904_1_AUTONEG_ADM_STATE, "Auto-Negotiation Admin State" },
    { DPOE_LB_1904_1_DUPLEX_STATUS,     "Duplex Status" },
    { DPOE_LB_1904_1_MAC_CTl_FUNCTIONS, "MAC Control Functions Supported" },
    { DPOE_LB_1904_1_RW_MAC_ADDRESS,    "Read/Write MAC Address" },
    { 0x070002,                         "Frames Tx OK" },
    { 0x070003,                         "Single Collision Frames" },
    { 0x070004,                         "Multiple Collision Frames" },
    { 0x070005,                         "Frames Rx OK" },
    { 0x070006,                         "FCS Errors" },
    { 0x070007,                         "Alignment Errors" },
    { 0x070008,                         "Octets Tx OK" },
    { 0x070009,                         "Frames With Deferred Transmissions" },
    { 0x07000A,                         "Late Collisions" },
    { 0x07000B,                         "Frames Aborted Collisions" },
    { 0x07000C,                         "Frames Lost Internal Tx Error" },
    { 0x07000E,                         "Octets Rx OK" },
    { 0x07000F,                         "Frames Lost Internal Rx Error" },
    { 0x070012,                         "Multicast Frames Tx OK" },
    { 0x070013,                         "Broadcast Frames Tx OK" },
    { 0x070014,                         "Frames With Excessive Deferral" },
    { 0x070015,                         "Multicast Frames Rx OK" },
    { 0x070016,                         "Broadcast Frames Rx OK" },
    { 0x070017,                         "In Range Length Errors" },
    { 0x070018,                         "Out of Range Length" },
    { 0x070019,                         "Frame Too Long Errors" },
    { 0x070062,                         "PAUSE Frames Tx" },
    { 0x070063,                         "PAUSE Frames Rx" },
    { 0x070118,                         "MPCP Frames TX" },
    { 0x070119,                         "MPCP Frames RX" },
    { 0x070120,                         "MPCP Discovery Windows Tx" },
    { 0x070122,                         "MPCP Discovery Timeout" },
    { 0x070124,                         "FEC Corrected Blocks" },
    { 0x070125,                         "FEC Uncorrectable Blocks" },
    { 0x07013C,                         "REGISTER_ACK MPCPDUs Tx" },
    { 0x07013E,                         "REGISTER_REQ MCCPDUs Tx" },
    { 0x07013F,                         "REPORT MPCPDUs Tx" },
    { 0x070140,                         "GATE MPCPDUs Rx" },
    { 0x070142,                         "REGISTER MPCPDUs Rx" },
    { 0, NULL }
};

static const value_string dpoe_variable_response_code_vals[] = {
    { 0x80, "No Error" },
    { 0x81, "Too Long" },
    { 0x86, "Bad Parameters" },
    { 0x87, "No Resources" },
    { 0x88, "System Busy" },
    { 0xA0, "Undetermined Error" },
    { 0xA1, "Unsupported" },
    { 0xA2, "May Be Corrupted" },
    { 0xA3, "Hardware Failure" },
    { 0xA4, "Overflow" },
    { 0, NULL }
};

static const value_string dpoe_1904_1_mac_enable_status_vals[] = {
    { 0x00, "disabled" },
    { 0x01, "enabled" },
    { 0, NULL }
};

static const value_string dpoe_1904_1_a_phy_type_vals[] = {
    { 0x01, "other" },
    { 0x02, "unknown" },
    { 0x03, "none" },
    { 0x07, "10Mbps" },
    { 0x17, "100BASE-T4" },
    { 0x18, "100BASE-X" },
    { 0x20, "100BASE-T2" },
    { 0x24, "1000BASE-X" },
    { 0x28, "1000BASE-T" },
    { 0x30, "10GBASE-X" },
    { 0x31, "10GBASE-R" },
    { 0x32, "10GBASE-W" },
    { 0x37, "10GBASE-T" },
    { 0x7d, "2.5GBASE-T" },
    { 0x7e, "5GBASE-T" },
    { 0, NULL }
};

static const value_string dpoe_1904_1_media_available_vals[] = {
    { 0x03, "available" },
    { 0x04, "not_available" },
    { 0, NULL }
};

static const value_string dpoe_1904_1_autoneg_admstate_vals[] = {
    { 0x00000001, "disabled" },
    { 0x00000002, "enabled" },
    { 0, NULL }
};

static const value_string dpoe_1904_1_duplex_status_vals[] = {
    { 0x01, "half_duplex" },
    { 0x02, "full_duplex" },
    { 0x03, "unknown" },
    { 0, NULL }
};

static const value_string dpoe_1904_1_cfg_mcast_llid_action[] = {
    { 0x00, "Add" },
    { 0x01, "Delete" },
    { 0x02, "Delete All" },
    { 0, NULL }
};

static const value_string user_port_object_subtype_vals[] = {
    { 0x00, "Terminator" },
    { 0x01, "Header" },
    { 0x02, "Clause" },
    { 0x03, "Result" },
    { 0, NULL }
};

static const value_string user_port_object_clause_fc_vals[] = {
    { 0x00, "LLID Index" },
    { 0x01, "L2 Destination MAC address" },
    { 0x02, "L2 Source MAC address" },
    { 0x03, "L2 Type/Len" },
    { 0x04, "B-DA ([802.1ah])" },
    { 0x05, "B-SA ([802.1ah])" },
    { 0x06, "I-Tag ([802.1ah])" },
    { 0x07, "S-VLAN Tag" },
    { 0x08, "C-VLAN Tag" },
    { 0x09, "MPLS" },
    { 0x0A, "IPv4 TOS/IPv6 Traffic Class" },
    { 0x0B, "IPv4 TTL/IPv6 Hop Limit" },
    { 0x0C, "IPv4/IPv6 Protocol Type" },
    { 0x0D, "IPv4 Source Address" },
    { 0x0E, "IPv6 Source Address" },
    { 0x0F, "IPv4 Destination Address" },
    { 0x10, "IPv6 Destination Address" },
    { 0x11, "IPv6 Next Header" },
    { 0x12, "IPv6 Flow Label" },
    { 0x13, "TCP/UDP source port" },
    { 0x14, "TCP/UDP destination port" },
    { 0x15, "Reserved" },
    { 0x16, "Reserved" },
    { 0x17, "Reserved" },
    { 0x18, "Custom field 0" },
    { 0x19, "Custom field 1" },
    { 0x1A, "Custom field 2" },
    { 0x1B, "Custom field 3" },
    { 0x1C, "Custom field 4" },
    { 0x1D, "Custom field 5" },
    { 0x1E, "Custom field 6" },
    { 0x1F, "Custom field 7" },
    { 0, NULL }
};

static const value_string user_port_object_clause_operator_vals[] = {
    { 0x00, "F" },
    { 0x01, "==" },
    { 0x02, "!=" },
    { 0x03, "<=" },
    { 0x04, ">=" },
    { 0x05, "exists" },
    { 0x06, "!exist" },
    { 0x07, "T" },
    { 0, NULL }
};

static const value_string user_port_object_result_rr_vals[] = {
    { 0x00, "NOP" },
    { 0x01, "Discard" },
    { 0x02, "Forward" },
    { 0x03, "Queue" },
    { 0x04, "Set" },
    { 0x05, "Copy" },
    { 0x06, "Delete" },
    { 0x07, "Insert" },
    { 0x08, "Replace" },
    { 0x09, "Clear Delete" },
    { 0x0A, "Clear Insert" },
    { 0, NULL }
};

static const value_string dpoe_oam_object_type_vals[] = {
    { DPOE_OBJ_CTX_ONU, "D-ONU" },
    { DPOE_OBJ_CTX_NETWORK_PORT, "Network PON Port" },
    { DPOE_OBJ_CTX_UCAST_LOGICAL_LINK, "Unicast Logical Link" },
    { DPOE_OBJ_CTX_S_INTERFACE, "User Port" },
    { DPOE_OBJ_CTX_QUEUE, "Queue" },
    { DPOE_OBJ_CTX_MEP, "MEP" },
    { DPOE_OBJ_CTX_MCAST_LOGICAL_LINK, "Multicast Logical Link" },
    { DPOE_OBJ_CTX_RESERVED, "Reserved" },
    { 0, NULL }
};

static const unit_name_string units_pdus_100ms = { " (PDUs/100ms)", NULL };
static const unit_name_string units_num_100ms = { " (Number of 100ms)", NULL };
static const unit_name_string units_1k = { " (KB)", NULL };

static dgt_set_t Dgt0_9_bcd = {
    {
        /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
           '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?','?'
    }
};

/* Initialise the protocol and registered fields */
static int proto_oampdu;

static int hf_oampdu_flags;
static int hf_oampdu_flags_link_fault;
static int hf_oampdu_flags_dying_gasp;
static int hf_oampdu_flags_critical_event;
static int hf_oampdu_flags_local_evaluating;
static int hf_oampdu_flags_local_stable;
static int hf_oampdu_flags_remote_evaluating;
static int hf_oampdu_flags_remote_stable;
static int hf_oampdu_code;

static int hf_oampdu_info_type;
static int hf_oampdu_info_len;
static int hf_oampdu_info_version;
static int hf_oampdu_info_revision;
static int hf_oampdu_info_state;
static int hf_oampdu_info_oamConfig;
static int hf_oampdu_info_oampduConfig;
static int hf_oampdu_info_oui;
static int hf_oampdu_info_vendor;
/* static int hf_oampdu_info_dpoe_oam_version; */
static int hf_oampdu_info_state_parser;
static int hf_oampdu_info_state_mux;

static int hf_oampdu_info_oamConfig_mode;
static int hf_oampdu_info_oamConfig_uni;
static int hf_oampdu_info_oamConfig_lpbk;
static int hf_oampdu_info_oamConfig_event;
static int hf_oampdu_info_oamConfig_var;

static int hf_oampdu_event_type;
static int hf_oampdu_event_sequence;
static int hf_oampdu_event_length;
static int hf_oampdu_event_timeStamp;

static int hf_oampdu_event_espeWindow;
static int hf_oampdu_event_espeThreshold;
static int hf_oampdu_event_espeErrors;
static int hf_oampdu_event_espeTotalErrors;
static int hf_oampdu_event_espeTotalEvents;

static int hf_oampdu_event_efeWindow;
static int hf_oampdu_event_efeThreshold;
static int hf_oampdu_event_efeErrors;
static int hf_oampdu_event_efeTotalErrors;
static int hf_oampdu_event_efeTotalEvents;

static int hf_oampdu_event_efpeWindow;
static int hf_oampdu_event_efpeThreshold;
static int hf_oampdu_event_efpeErrors;
static int hf_oampdu_event_efpeTotalErrors;
static int hf_oampdu_event_efpeTotalEvents;

static int hf_oampdu_event_efsseWindow;
static int hf_oampdu_event_efsseThreshold;
static int hf_oampdu_event_efsseErrors;
static int hf_oampdu_event_efsseTotalErrors;
static int hf_oampdu_event_efsseTotalEvents;

static int hf_oampdu_variable_branch;
static int hf_oampdu_variable_object;
static int hf_oampdu_variable_package;
static int hf_oampdu_variable_binding;
static int hf_oampdu_variable_attribute;
static int hf_oampdu_variable_width;
static int hf_oampdu_variable_indication;
static int hf_oampdu_variable_value;
/* static int hf_oampdu_vendor_specific_opcode; */
static int hf_oampdu_vendor_specific_dpoe_opcode;
static int hf_oampdu_vendor_specific_dpoe_evt_code;
static int hf_oampdu_vendor_specific_dpoe_evt_raised;
static int hf_oampdu_vendor_specific_dpoe_evt_object_type;
static int hf_dpoe_variable_descriptor;
static int hf_dpoe_variable_response_code;
static int hf_oam_dpoe_response_eth;
static int hf_oam_dpoe_response_int;

static int hf_oam_dpoe_fw_info_boot_version;
static int hf_oam_dpoe_fw_info_boot_crc;
static int hf_oam_dpoe_fw_info_fw_version;
static int hf_oam_dpoe_fw_info_fw_crc;
static int hf_oam_dpoe_date_of_manufacture;
static int hf_oam_dpoe_chipset_jedec_id;
static int hf_oam_dpoe_chipset_chip_model;
static int hf_oam_dpoe_chipset_chip_version;
static int hf_oam_dpoe_mfg_info_serial_number;
static int hf_oam_dpoe_mfg_info_vendor_specific;
static int hf_oam_dpoe_mll_b;
static int hf_oam_dpoe_mll_do;
static int hf_oam_dpoe_pkt_buffer_us_queues;
static int hf_oam_dpoe_pkt_buffer_us_queues_max_per_link;
static int hf_oam_dpoe_pkt_buffer_us_queue_inc;
static int hf_oam_dpoe_pkt_buffer_ds_queues;
static int hf_oam_dpoe_pkt_buffer_ds_queues_max_per_link;
static int hf_oam_dpoe_pkt_buffer_ds_queue_inc;
static int hf_oam_dpoe_pkt_buffer_total_memory;
static int hf_oam_dpoe_pkt_buffer_us_memory_max;
static int hf_oam_dpoe_pkt_buffer_ds_memory_max;
static int hf_oam_dpoe_frame_rate_minimum;
static int hf_oam_dpoe_frame_rate_maximum;
static int hf_oam_dpoe_mfg_org_name;
static int hf_oam_dpoe_tvc_code_access_start;
static int hf_oam_dpoe_tvc_cvc_access_start;
static int hf_oam_dpoe_vendor_name;
static int hf_oam_dpoe_model_number;
static int hf_oam_dpoe_hw_version;
static int hf_oam_dpoe_sw_bundle;
static int hf_oam_dpoe_repthr_nqs;
static int hf_oam_dpoe_repthr_rvpqs;
static int hf_oam_dpoe_report_threshold;
static int hf_oam_dpoe_ll_fwd_state;
static int hf_oam_dpoe_s1_autoneg;
static int hf_oam_dpoe_s1_autoneg_hd;
static int hf_oam_dpoe_s1_autoneg_fd;
static int hf_oam_dpoe_s1_autoneg_10;
static int hf_oam_dpoe_s1_autoneg_100;
static int hf_oam_dpoe_s1_autoneg_1000;
static int hf_oam_dpoe_s1_autoneg_10000;
static int hf_oam_dpoe_s1_autoneg_fc;
static int hf_oam_dpoe_s1_autoneg_mdi;
static int hf_oam_dpoe_user_port_object;
static int hf_oam_dpoe_user_port_object_subtype;
static int hf_oam_dpoe_user_port_object_header_precedence;
static int hf_oam_dpoe_user_port_object_clause_fc;
static int hf_oam_dpoe_user_port_object_clause_fi;
static int hf_oam_dpoe_user_port_object_clause_msbm;
static int hf_oam_dpoe_user_port_object_clause_lsbm;
static int hf_oam_dpoe_user_port_object_clause_operator;
static int hf_oam_dpoe_user_port_object_clause_mvl;
static int hf_oam_dpoe_user_port_object_clause_mv;
static int hf_oam_dpoe_user_port_object_result_rr;
static int hf_oam_dpoe_user_port_object_result_rr_queue_obj_type;
static int hf_oam_dpoe_user_port_object_result_rr_queue_obj_inst;
static int hf_oam_dpoe_user_port_object_result_rr_queue_queue_index;
static int hf_oam_dpoe_user_port_object_result_rr_set_fc;
static int hf_oam_dpoe_user_port_object_result_rr_set_fi;
static int hf_oam_dpoe_user_port_object_result_rr_copy;
static int hf_oam_dpoe_user_port_object_result_rr_delete;
static int hf_oam_dpoe_user_port_object_result_rr_insert;
static int hf_oam_dpoe_user_port_object_result_rr_replace;
static int hf_oam_dpoe_user_port_object_result_rr_cd;
static int hf_oam_dpoe_user_port_object_result_rr_ci;
static int hf_oam_dpoe_qc_ll_u;
static int hf_oam_dpoe_qc_ports_d;
static int hf_oam_dpoe_qc_nq;
static int hf_oam_dpoe_qc_queue_size;
static int hf_oam_dpoe_fw_filename;
static int hf_oam_dpoe_onu_port_config_llid_count;
static int hf_oam_dpoe_onu_port_config_uni_count;

static int hf_oam_dpoe_1904_1_mac_enable_status;
static int hf_oam_dpoe_1904_1_a_phy_type;
static int hf_oam_dpoe_1904_1_media_available;
static int hf_oam_dpoe_1904_1_autoneg_admstate;
static int hf_oam_dpoe_1904_1_duplex_status;
static int hf_oam_dpoe_1904_1_mac_control_functions_supported;
static int hf_oam_dpoe_1904_1_cfg_mcast_llid_action;
static int hf_oam_dpoe_1904_1_cfg_mcast_llid_value;
static int hf_oam_dpoe_1904_1_read_write_mac_address;
static int hf_oam_dpoe_1904_1_qc_queue_size;

static int hf_oampdu_lpbk;
static int hf_oampdu_lpbk_enable;
static int hf_oampdu_lpbk_disable;

static int ett_oampdu_vendor_specific;
static int ett_dpoe_opcode;
static int ett_dpoe_opcode_response;
static int ett_oam_dpoe_s1_autoneg;
static int ett_oam_dpoe_qc_u;
static int ett_oam_dpoe_qc_d;
static int ett_oam_dpoe_qc_nq;

/* Initialise the subtree pointers */

static int ett_oampdu;
static int ett_oampdu_flags;

static int ett_oampdu_local_info;
static int ett_oampdu_local_info_state;
static int ett_oampdu_local_info_config;
static int ett_oampdu_remote_info;
static int ett_oampdu_remote_info_state;
static int ett_oampdu_remote_info_config;
static int ett_oampdu_org_info;

static int ett_oampdu_event_espe;
static int ett_oampdu_event_efe;
static int ett_oampdu_event_efpe;
static int ett_oampdu_event_efsse;
static int ett_oampdu_event_ose;

static int ett_oampdu_lpbk_ctrl;

static expert_field ei_oampdu_event_length_bad;
static expert_field ei_oampdu_mvl_length_zero;

static void
dissect_oampdu_information(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_event_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_oampdu_variable_request(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_variable_response(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_loopback_control(tvbuff_t *tvb, proto_tree *tree);

static void
dissect_oampdu_vendor_specific(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_cablelabs_event_notification(tvbuff_t *tvb, proto_tree *tree, uint8_t bytes, uint32_t offset);

/*
 * Name: dissect_oampdu
 *
 * Description:
 *    This function is used to dissect the Operation, Administration, and
 *    Maintenance slow protocol defined in IEEE 802.3 clause 57 (The OAMPDUs
 *    common part is defined in section 57.4).
 *
 *    Only the 6 following codes are currently defined in the 2004 version of this
 *    protocol:

 *       OAMPDU_INFORMATION:        0x0
 *       OAMPDU_EVENT_NOTIFICATION: 0x1
 *       OAMPDU_VAR_REQUEST:        0x2
 *       OAMPDU_VAR_RESPONSE:       0x3
 *       OAMPDU_LOOPBACK_CTRL:      0x4
 *       OAMPDU_VENDOR_SPECIFIC:    0xFE
 *
 * Input Arguments:
 *    tvb:   buffer associated with the rcv packet (see tvbuff.h).
 *    pinfo: structure associated with the rcv packet (see packet_info.h).
 *    tree:  the protocol tree associated with the rcv packet (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static int
dissect_oampdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int       offset = 0;
    uint8_t   oampdu_code;

    proto_tree *oampdu_tree;
    proto_item *oampdu_item;

    static int * const oampdu_flags[] = {
        &hf_oampdu_flags_link_fault,
        &hf_oampdu_flags_dying_gasp,
        &hf_oampdu_flags_critical_event,
        &hf_oampdu_flags_local_evaluating,
        &hf_oampdu_flags_local_stable,
        &hf_oampdu_flags_remote_evaluating,
        &hf_oampdu_flags_remote_stable,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OAM");
    col_clear(pinfo->cinfo, COL_INFO);

    oampdu_item = proto_tree_add_protocol_format(tree, proto_oampdu,
            tvb, 0, -1, "OAM Protocol");
    oampdu_tree = proto_item_add_subtree(oampdu_item, ett_oampdu);

    /* Flags field */
    proto_tree_add_bitmask_with_flags(oampdu_tree, tvb, offset, hf_oampdu_flags, ett_oampdu_flags, oampdu_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE|BMT_NO_TFS);
    offset += 2;

    /* OAMPDU code */
    oampdu_code = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(oampdu_tree, hf_oampdu_code, tvb,
          offset, 1, oampdu_code);

    col_add_fstr(pinfo->cinfo, COL_INFO, "OAMPDU: %s", val_to_str_const(oampdu_code, code_vals, "Unknown"));

    switch (oampdu_code)
    {
        case OAMPDU_INFORMATION:
            dissect_oampdu_information(tvb, oampdu_tree);
            break;
        case OAMPDU_EVENT_NOTIFICATION:
            dissect_oampdu_event_notification(tvb, pinfo, oampdu_tree);
            break;
        case OAMPDU_VAR_REQUEST:
            dissect_oampdu_variable_request(tvb, oampdu_tree);
            break;
        case OAMPDU_VAR_RESPONSE:
            dissect_oampdu_variable_response(tvb, oampdu_tree);
            break;
        case OAMPDU_LOOPBACK_CTRL:
            dissect_oampdu_loopback_control(tvb, oampdu_tree);
            break;
        case OAMPDU_VENDOR_SPECIFIC:
            dissect_oampdu_vendor_specific(tvb, pinfo, oampdu_tree);
        default:
            break;
    }
	return tvb_captured_length(tvb);
}

/*
 * Name: dissect_oampdu_information
 *
 * Description:
 *    This function is used to dissect the Information TLVs defined in IEEE802.3
 *    section 57.5.2.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_information(tvbuff_t *tvb, proto_tree *tree)
{
    uint8_t   raw_octet;
    uint8_t   info_type;
    uint32_t  offset;
    uint16_t  bytes;

    proto_tree *info_tree;
    proto_item *info_item;


    offset = OAMPDU_HEADER_SIZE;

    while (1)
    {
        bytes = tvb_captured_length_remaining(tvb, offset);
        if (bytes < 1) break;

        info_type = tvb_get_uint8(tvb, offset);

        if (info_type == OAMPDU_INFO_TYPE_ENDMARKER) break;

        info_item = proto_tree_add_uint(tree, hf_oampdu_info_type, tvb,
                offset, 1, info_type);

        switch (info_type)
        {
            case OAMPDU_INFO_TYPE_LOCAL:
                info_tree = proto_item_add_subtree(info_item, ett_oampdu_local_info);
                break;
            case OAMPDU_INFO_TYPE_REMOTE:
                info_tree = proto_item_add_subtree(info_item, ett_oampdu_remote_info);
                break;
            case OAMPDU_INFO_TYPE_ORG:
                info_tree = proto_item_add_subtree(info_item, ett_oampdu_org_info);
                break;
            default:
                info_tree = NULL;
                break;
        }

        offset += OAMPDU_INFO_TYPE_SZ;

        if ((info_type==OAMPDU_INFO_TYPE_LOCAL)||(info_type==OAMPDU_INFO_TYPE_REMOTE))
        {
            static int * const info_states[] = {
                &hf_oampdu_info_state_parser,
                &hf_oampdu_info_state_mux,
                NULL
            };
            static int * const info_config[] = {
                &hf_oampdu_info_oamConfig_mode,
                &hf_oampdu_info_oamConfig_uni,
                &hf_oampdu_info_oamConfig_lpbk,
                &hf_oampdu_info_oamConfig_event,
                &hf_oampdu_info_oamConfig_var,
                NULL
            };

            proto_tree_add_item(info_tree, hf_oampdu_info_len,
                    tvb, offset, 1, ENC_BIG_ENDIAN);

            offset += OAMPDU_INFO_LENGTH_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_version,
                    tvb, offset, 1, ENC_BIG_ENDIAN);

            offset += OAMPDU_INFO_VERSION_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_revision,
                    tvb, offset, 2, ENC_BIG_ENDIAN);

            offset += OAMPDU_INFO_REVISION_SZ;

            /* Build OAM State field field */
            raw_octet = tvb_get_uint8(tvb, offset);
            if (raw_octet == OAMPDU_INFO_TYPE_LOCAL)
                proto_tree_add_bitmask(info_tree, tvb, offset, hf_oampdu_info_state, ett_oampdu_local_info_state, info_states, ENC_NA);
            else
                proto_tree_add_bitmask(info_tree, tvb, offset, hf_oampdu_info_state, ett_oampdu_remote_info_state, info_states, ENC_NA);

            offset += OAMPDU_INFO_STATE_SZ;

            /* Build OAM configuration field */
            raw_octet = tvb_get_uint8(tvb, offset);
            if (raw_octet == OAMPDU_INFO_TYPE_LOCAL)
                proto_tree_add_bitmask(info_tree, tvb, offset, hf_oampdu_info_oamConfig, ett_oampdu_local_info_config, info_config, ENC_NA);
            else
                proto_tree_add_bitmask(info_tree, tvb, offset, hf_oampdu_info_oamConfig, ett_oampdu_remote_info_config, info_config, ENC_NA);

            offset += OAMPDU_INFO_OAM_CONFIG_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_oampduConfig,
                    tvb, offset, 2, ENC_BIG_ENDIAN);

            offset += OAMPDU_INFO_OAMPDU_CONFIG_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_oui,
                    tvb, offset, 3, ENC_BIG_ENDIAN);

            offset += OAMPDU_INFO_OUI_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_vendor,
                    tvb, offset, 4, ENC_NA);

            offset += OAMPDU_INFO_VENDOR_SPECIFIC_SZ;
        }
        else if (info_type == OAMPDU_INFO_TYPE_ORG)
        {
            /* see IEEE802.3, section 57.5.2.3 for more details */
            raw_octet = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(info_tree, hf_oampdu_info_len,
                    tvb, offset, 1, ENC_BIG_ENDIAN);

            offset += OAMPDU_INFO_LENGTH_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += OAMPDU_INFO_OUI_SZ;

            proto_tree_add_item(info_tree, hf_oampdu_info_vendor,
                    tvb, offset, raw_octet-5, ENC_NA);

            offset += raw_octet-5;

        }
        else
        {
            /* If it's a unknown type jump over */
            raw_octet = tvb_get_uint8(tvb, offset);
            offset += raw_octet;
        }
    }
}

/*
 * Name: dissect_oampdu_event_notification
 *
 * Description:
 *    This function is used to dissect the Event Notification TLVs defined in
 *    IEEE802.3 section 57.5.3.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_event_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    uint8_t   raw_octet;

    uint8_t   event_type;
    uint32_t  offset;
    uint16_t  bytes;

    proto_tree *event_tree;
    proto_item *event_item;

    offset = OAMPDU_HEADER_SIZE;

    /* Display the sequence number before displaying the TLVs */
    proto_tree_add_item(tree, hf_oampdu_event_sequence,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += OAMPDU_EVENT_SEQUENCE_SZ;

    while (1)
    {
        bytes = tvb_captured_length_remaining(tvb, offset);
        if (bytes < 1) break;

        event_type = tvb_get_uint8(tvb, offset);

        if (event_type == OAMPDU_EVENT_TYPE_END) break;

        event_item = proto_tree_add_uint(tree, hf_oampdu_event_type,
                tvb, offset, 1, event_type);

        offset += OAMPDU_EVENT_TYPE_SZ;

        switch (event_type)
        {
            case OAMPDU_EVENT_TYPE_ESPE:
                event_tree = proto_item_add_subtree(event_item,
                        ett_oampdu_event_espe);

                proto_tree_add_item(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_LENGTH_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_espeWindow,
                        tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += OAMPDU_ESPE_WINDOW_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_espeThreshold,
                        tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += OAMPDU_ESPE_THRESHOLD_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_espeErrors,
                        tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += OAMPDU_ESPE_ERRORS_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_espeTotalErrors,
                        tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += OAMPDU_ESPE_ERR_TOTAL_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_espeTotalEvents,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_ESPE_TOTAL_SZ;
                break;

            case OAMPDU_EVENT_TYPE_EFE:
                event_tree = proto_item_add_subtree(event_item,
                        ett_oampdu_event_efe);

                proto_tree_add_item(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_LENGTH_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efeWindow,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFE_WINDOW_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efeThreshold,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFE_THRESHOLD_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efeErrors,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFE_ERRORS_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efeTotalErrors,
                        tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFE_ERR_TOTAL_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efeTotalEvents,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFE_TOTAL_SZ;
                break;

            case OAMPDU_EVENT_TYPE_EFPE:
                event_tree = proto_item_add_subtree(event_item,
                        ett_oampdu_event_efpe);

                proto_tree_add_item(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_LENGTH_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efpeWindow,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFPE_WINDOW_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efpeThreshold,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFPE_THRESHOLD_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efpeErrors,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFPE_ERRORS_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efpeTotalErrors,
                        tvb, offset, 8, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFPE_ERR_TOTAL_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efpeTotalEvents,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFPE_TOTAL_SZ;
                break;

            case OAMPDU_EVENT_TYPE_EFSSE:
                event_tree = proto_item_add_subtree(event_item,
                        ett_oampdu_event_efsse);

                proto_tree_add_item(event_tree, hf_oampdu_event_length,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_LENGTH_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_timeStamp,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EVENT_TIMESTAMP_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efsseWindow,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFSSE_WINDOW_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efsseThreshold,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFSSE_THRESHOLD_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efsseErrors,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFSSE_ERRORS_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efsseTotalErrors,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFSSE_ERR_TOTAL_SZ;

                proto_tree_add_item(event_tree, hf_oampdu_event_efsseTotalEvents,
                        tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += OAMPDU_EFSSE_TOTAL_SZ;
                break;

            case OAMPDU_EVENT_TYPE_OSE:
                {
                    event_tree = proto_item_add_subtree(event_item,
                            ett_oampdu_event_ose);

                    raw_octet = tvb_get_uint8(tvb, offset);
                    event_item = proto_tree_add_uint(event_tree, hf_oampdu_event_length,
                            tvb, offset, 1, raw_octet);

                    offset += OAMPDU_EVENT_LENGTH_SZ;

                    if (raw_octet < 2)
                    {
                        expert_add_info_format(pinfo, event_item, &ei_oampdu_event_length_bad, "Event length should be at least 2");
                    }
                    else
                    {
                        uint32_t event_oui;
                        uint32_t cable_labs_oui = (OUI_CL_0 << 16) + (OUI_CL_1 << 8) + OUI_CL_2;

                        event_oui = tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN);
                        if (event_oui == cable_labs_oui)
                        {
                            dissect_cablelabs_event_notification(tvb, event_tree, raw_octet, offset);
                        }
                        else
                        {
                            offset += (raw_octet-2);
                        }
                    }
                    break;
                }
            default:
                break;
        }
    }
}

/*
 * Name: dissect_oampdu_variable_request
 *
 * Description:
 *    This function is used to dissect the Variable Request TLVs defined in
 *    IEEE802.3 section 57.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_variable_request(tvbuff_t *tvb, proto_tree *tree)
{
    uint8_t   raw_octet;
    uint32_t  offset;


    offset = OAMPDU_HEADER_SIZE;

    while (1)
    {
        raw_octet = tvb_get_uint8(tvb, offset);

        if (raw_octet == 0) break;

        proto_tree_add_uint(tree, hf_oampdu_variable_branch,
                tvb,offset, 1, raw_octet);

        offset+=1;

        switch (raw_octet)
        {
            case OAMPDU_VARS_OBJECT:
                proto_tree_add_item(tree, hf_oampdu_variable_object,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case OAMPDU_VARS_PACKAGE:
                proto_tree_add_item(tree, hf_oampdu_variable_package,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case OAMPDU_VARS_BINDING:
                proto_tree_add_item(tree, hf_oampdu_variable_binding,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case OAMPDU_VARS_ATTRIBUTE:
                proto_tree_add_item(tree, hf_oampdu_variable_attribute,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            default:
                break;
        }

        offset+=2;
    }
}

/*
 * Name: dissect_oampdu_variable_response
 *
 * Description:
 *    This function is used to dissect the Variable Response TLVs defined in
 *    IEEE802.3 section 57.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_variable_response(tvbuff_t *tvb, proto_tree *tree)
{
    uint8_t   branch, raw_octet;
    uint32_t  offset;

    offset = OAMPDU_HEADER_SIZE;

    while (1)
    {
        branch = tvb_get_uint8(tvb, offset);

        if (branch == 0) break;

        proto_tree_add_uint(tree, hf_oampdu_variable_branch,
                            tvb,offset, 1, branch);

        offset+=1;

        switch (branch)
        {
            case OAMPDU_VARS_OBJECT:
                proto_tree_add_item(tree, hf_oampdu_variable_object,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case OAMPDU_VARS_PACKAGE:
                proto_tree_add_item(tree, hf_oampdu_variable_package,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case OAMPDU_VARS_BINDING:
                proto_tree_add_item(tree, hf_oampdu_variable_binding,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case OAMPDU_VARS_ATTRIBUTE:
                proto_tree_add_item(tree, hf_oampdu_variable_attribute,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            default:
                break;
        }
        offset+=2;

        do {
            raw_octet = tvb_get_uint8(tvb, offset);

            if (raw_octet >= 0x80) {
                /* Variable Indication */
                proto_tree_add_uint(tree, hf_oampdu_variable_indication,
                                    tvb,offset, 1, (raw_octet&0x7F));
                offset+=1;
                break;
            }
            else {
                /* Length field and data */

                /* Length field 0 means the length is 128 bytes */
                if (raw_octet == 0) raw_octet = 128;

                proto_tree_add_uint(tree, hf_oampdu_variable_width,
                        tvb,offset, 1, raw_octet);
                offset+=1;

                proto_tree_add_item(tree, hf_oampdu_variable_value,
                        tvb, offset, raw_octet, ENC_NA);
                offset+=raw_octet;
            }
            /* object and package containers consist of multiple entries
               (variable indication + variable value), the last entry
               has only the variable indication and no value
               binding and attribute objects have only one such entry */
        } while (branch==OAMPDU_VARS_OBJECT || branch==OAMPDU_VARS_PACKAGE);
    }
}

/*
 * Name: dissect_oampdu_loopback_control
 *
 * Description:
 *    This function is used to dissect the Variable Request TLVs defined in
 *    IEEE802.3 section 57.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 */
static void
dissect_oampdu_loopback_control(tvbuff_t *tvb, proto_tree *tree)
{
    uint32_t  offset;
    uint16_t  bytes;

    static int * const ctrl[] = {
        &hf_oampdu_lpbk_enable,
        &hf_oampdu_lpbk_disable,
        NULL
    };

    offset = OAMPDU_HEADER_SIZE;

    bytes = tvb_captured_length_remaining(tvb, offset);

    if (bytes >= 1)
    {
        proto_tree_add_bitmask(tree, tvb, offset, hf_oampdu_lpbk, ett_oampdu_lpbk_ctrl, ctrl, ENC_NA);
    }
}

static int * const s1_autoneg_mode_bits[] = {
    &hf_oam_dpoe_s1_autoneg_hd,
    &hf_oam_dpoe_s1_autoneg_fd,
    &hf_oam_dpoe_s1_autoneg_10,
    &hf_oam_dpoe_s1_autoneg_100,
    &hf_oam_dpoe_s1_autoneg_1000,
    &hf_oam_dpoe_s1_autoneg_10000,
    &hf_oam_dpoe_s1_autoneg_fc,
    &hf_oam_dpoe_s1_autoneg_mdi,
    NULL
  };

static void dissect_oampdu_add_queue_object(proto_tree *tree, tvbuff_t *tvb, int offset)
{
        proto_tree_add_item(tree,
                            hf_oam_dpoe_user_port_object_result_rr_queue_obj_type,
                            tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree,
                            hf_oam_dpoe_user_port_object_result_rr_queue_obj_inst,
                            tvb, offset+2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree,
                            hf_oam_dpoe_user_port_object_result_rr_queue_queue_index,
                            tvb, offset+3, 1, ENC_BIG_ENDIAN);
}


/*
 * Name: dissect_oampdu_vendor_specific
 *
 * Description:
 *    This function is used to dissect the Vendor Specific TLV defined in
 *    IEEE802.3 section 57.4.3.6.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *
 * Return Values: None
 *
 * Notes:
 *    Dominique Bastien (dbastien@accedian.com)
 *      + add support for 802.3ah-2004.
 *    Philip Rosenberg-Watt (p.rosenberg-watt[at]cablelabs.com)
 *      + add support for CableLabs DPoE OAM Extensions Specification
 */
static void
dissect_oampdu_vendor_specific(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    uint32_t  offset;
    uint16_t  bytes;
    uint32_t  leaf_branch;
    uint8_t   dpoe_opcode;
    uint8_t   variable_length;
    uint8_t   next_byte;
    uint8_t   pir_subtype;
    uint8_t   rr_byte;

    static const uint8_t oui_cl[] = {OUI_CL_0, OUI_CL_1, OUI_CL_2};

    proto_item *oui_item;
    proto_item *event_item;
    proto_tree *oampdu_vendor_specific_tree;
    proto_tree *dpoe_opcode_tree;
    proto_item *dpoe_opcode_item;
    proto_item *dpoe_opcode_request_tree;
    proto_item *dpoe_opcode_request_item;
    proto_item *dpoe_opcode_response;
    proto_tree *dpoe_opcode_response_tree;
    offset = OAMPDU_HEADER_SIZE;

    bytes = tvb_captured_length_remaining(tvb, offset);

    if (bytes >= 3) {
        oui_item = proto_tree_add_item(tree, hf_oampdu_info_oui, tvb, offset, 3, ENC_BIG_ENDIAN);

        if (tvb_memeql(tvb, offset, oui_cl, OUI_SIZE) == 0) {

            offset += 3;

            oampdu_vendor_specific_tree = proto_item_add_subtree(oui_item, ett_oampdu_vendor_specific);
            dpoe_opcode_item = proto_tree_add_item(oampdu_vendor_specific_tree, hf_oampdu_vendor_specific_dpoe_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
            dpoe_opcode_tree = proto_item_add_subtree(dpoe_opcode_item, ett_dpoe_opcode);
            dpoe_opcode = tvb_get_uint8(tvb, offset);
            offset +=1;
            next_byte = tvb_get_uint8(tvb, offset);
            switch (dpoe_opcode) {
                case 0x00:
                    break;
                case DPOE_OPCODE_GET_REQUEST:
                    variable_length = 0;
                    while (next_byte != 0x00) {
                        leaf_branch = tvb_get_ntoh24(tvb, offset);
                        if (leaf_branch == DPOE_LB_ONU_OBJ || leaf_branch == DPOE_LB_LINK_OBJ || \
                            leaf_branch == DPOE_LB_USER_PORT_OBJ || leaf_branch == DPOE_LB_NETWORK_PORT_OBJ ||
                            leaf_branch == DPOE_LB_MC_LL_OBJ || leaf_branch == DPOE_LB_QUEUE_OBJ) {
                            dpoe_opcode_request_item = proto_tree_add_item(dpoe_opcode_tree, hf_dpoe_variable_descriptor, tvb, offset, 3, ENC_BIG_ENDIAN);
                            offset += 3;
                            variable_length = tvb_get_uint8(tvb, offset);
                            offset += 1;
                            if (variable_length == 1) {
                                /* Add User Port or Link instance */
                                dpoe_opcode_request_tree = proto_item_add_subtree(dpoe_opcode_request_item, ett_dpoe_opcode);
                                if (leaf_branch == DPOE_LB_USER_PORT_OBJ) {
                                    proto_tree_add_item(dpoe_opcode_request_tree, hf_oam_dpoe_user_port_object, tvb, offset, 1, ENC_BIG_ENDIAN);
                                } else {
                                    proto_tree_add_item(dpoe_opcode_request_tree, hf_oampdu_variable_value, tvb, offset, 1, ENC_NA);
                                }
                            } else if (variable_length == 4 && leaf_branch == DPOE_LB_QUEUE_OBJ) {
                                /* Add Queue object instance */
                                dpoe_opcode_request_tree = proto_item_add_subtree(dpoe_opcode_request_item, ett_dpoe_opcode);
                                dissect_oampdu_add_queue_object(dpoe_opcode_request_tree, tvb, offset);
                            }
                            offset += variable_length;
                            next_byte = tvb_get_uint8(tvb, offset);
                        } else {
                            proto_tree_add_item(dpoe_opcode_tree, hf_dpoe_variable_descriptor, tvb, offset, 3, ENC_BIG_ENDIAN);
                            offset += 3;
                            next_byte = tvb_get_uint8(tvb, offset);
                        }
                    }
                    break;
                case DPOE_OPCODE_GET_RESPONSE: /* Get-Response */
                case DPOE_OPCODE_SET_REQUEST: /* Set-Request */
                case DPOE_OPCODE_SET_RESPONSE: /* Set-Response */
                    while (next_byte != 0x00) {
                        dpoe_opcode_response = proto_tree_add_item(dpoe_opcode_tree, hf_dpoe_variable_descriptor, tvb, offset, 3, ENC_BIG_ENDIAN);
                        leaf_branch = tvb_get_ntoh24(tvb, offset);
                        offset += 3;
                        variable_length = tvb_get_uint8(tvb, offset);
                        dpoe_opcode_response_tree = proto_item_add_subtree(dpoe_opcode_response, ett_dpoe_opcode_response);
                        if (variable_length >= 0x80) {
                            proto_tree_add_item(dpoe_opcode_response_tree, hf_dpoe_variable_response_code, tvb, offset, 1, ENC_BIG_ENDIAN);
                            variable_length = 0;
                            offset += 1;
                        } else if (variable_length == 0) {
                            offset += 1;
                            variable_length = 128;
                            proto_tree_add_item(dpoe_opcode_response_tree, hf_oampdu_variable_value, tvb, offset, variable_length, ENC_NA);
                        } else {
                            offset += 1;
                            if (leaf_branch == (DPOE_LB_ONU_ID)) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_response_eth, tvb, offset, variable_length, ENC_NA);
                            } else if (leaf_branch == DPOE_LB_FW_INFO) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_fw_info_boot_version, tvb, offset, 2, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_fw_info_boot_crc, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_fw_info_fw_version, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_fw_info_fw_crc, tvb, offset+8, 4, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_MFG_INFO) {
                                char *serial_num;
                                serial_num = tvb_get_string_enc(pinfo->pool, tvb, offset, variable_length, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_mfg_info_serial_number, tvb, offset, variable_length, serial_num);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_mfg_info_vendor_specific, tvb, offset+32, variable_length-32, ENC_NA);
                            } else if (leaf_branch == DPOE_LB_DATE_OF_MANUFACTURE) {
                                const char *bcd_date;
                                uint16_t year;
                                uint8_t yearh;
                                uint8_t yearl;
                                uint8_t month;
                                uint8_t day;
                                char date[16];

                                /* ONU vendors do not all encode the year properly. Make a best guess as to how the year is encoded*/
                                year = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
                                yearh = (year >> 8) & 0xff;
                                yearl = year & 0xff;
                                month = tvb_get_uint8(tvb, offset+2);
                                day = tvb_get_uint8(tvb, offset+3);
                                memset(date, 0, sizeof(date));

                                /* Check for a BCD encoded year in the range 2000 - 2599 */
                                if (year >= 0x2000 && year <= 0x2599) {
                                    bcd_date = tvb_get_bcd_string(pinfo->pool, tvb, offset, 4, &Dgt0_9_bcd, false, false, true);
                                    date[0] = bcd_date[0];
                                    date[1] = bcd_date[1];
                                    date[2] = bcd_date[2];
                                    date[3] = bcd_date[3];
                                    date[4] = '/';
                                    date[5] = bcd_date[4];
                                    date[6] = bcd_date[5];
                                    date[7] = '/';
                                    date[8] = bcd_date[6];
                                    date[9] = bcd_date[7];
                                }
                                /* Check if year is encoded as two separate bytes */
                                else if (yearh >= 20 && yearh <= 25 && yearl <= 99) {
                                    snprintf(date, sizeof(date)-1, "%02hhd%02hhd/%02hhd/%02hhd", yearh, yearl, month, day);
                                }
                                /* Check if year is encoded as a two-byte value */
                                else if (year >= 2000 && year <= 2599) {
                                    snprintf(date, sizeof(date)-1, "%02hd/%02hhd/%02hhd", year, month, day);
                                } else {
                                    snprintf(date, sizeof(date)-1, "%s", "Unknown");
                                }
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_date_of_manufacture, tvb, offset, 4, date);
                            } else if (leaf_branch == DPOE_LB_CHIPSET_INFO) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_chipset_jedec_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_chipset_chip_model, tvb, offset+2, 4, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_chipset_chip_version, tvb, offset, 4, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_MAX_LL) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_mll_b, tvb, offset, 2, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_mll_do, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_MAX_NET_PORTS) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_response_int, tvb, offset, variable_length, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_NUM_S1_INT) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_response_int, tvb, offset, variable_length, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_PKT_BUFFER) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_us_queues, tvb, offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_us_queues_max_per_link, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_us_queue_inc, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_ds_queues, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_ds_queues_max_per_link, tvb, offset+4, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_ds_queue_inc, tvb, offset+5, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_total_memory, tvb, offset+6, 2, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_us_memory_max, tvb, offset+8, 2, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_pkt_buffer_ds_memory_max, tvb, offset+10, 2, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_OAM_FR) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_frame_rate_minimum, tvb, offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_frame_rate_maximum, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_MFG_ORG_NAME) {
                                char *mfg_org_name;
                                mfg_org_name = tvb_get_string_enc(pinfo->pool, tvb, offset, variable_length, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_mfg_org_name, tvb, offset, variable_length, mfg_org_name);
                            } else if (leaf_branch == DPOE_LB_TIME_VARYING_CONTROLS) {
                                char *access_start;
                                access_start = tvb_get_string_enc(pinfo->pool, tvb, offset, 13, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_tvc_code_access_start, tvb, offset, 13, access_start);
                                access_start = tvb_get_string_enc(pinfo->pool, tvb, offset+13, 13, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_tvc_cvc_access_start, tvb, offset+13, 13, access_start);
                            } else if (leaf_branch == DPOE_LB_VENDOR_NAME) {
                                char *vendor_name;
                                vendor_name = tvb_get_string_enc(pinfo->pool, tvb, offset, variable_length, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_vendor_name, tvb, offset, variable_length, vendor_name);
                            } else if (leaf_branch == DPOE_LB_MODEL_NUMBER) {
                                char *model_number;
                                model_number = tvb_get_string_enc(pinfo->pool, tvb, offset, variable_length, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_model_number, tvb, offset, variable_length, model_number);
                            } else if (leaf_branch == DPOE_LB_HW_VERSION) {
                                char *hw_version;
                                hw_version = tvb_get_string_enc(pinfo->pool, tvb, offset, variable_length, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_hw_version, tvb, offset, variable_length, hw_version);
                            } else if (leaf_branch == DPOE_LB_SW_BUNDLE) {
                                char *sw_bundle;
                                sw_bundle = tvb_get_stringzpad(pinfo->pool, tvb, offset, variable_length, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_sw_bundle, tvb, offset, variable_length, sw_bundle);
                            } else if (leaf_branch == DPOE_LB_REP_THRESH) {
                                uint8_t nqs;
                                uint8_t rvpqs;
                                uint8_t nqs_i;
                                uint8_t rvpqs_i;

                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_repthr_nqs, tvb, offset, 1, ENC_BIG_ENDIAN);
                                nqs = tvb_get_uint8(tvb, offset);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_repthr_rvpqs, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                                rvpqs = tvb_get_uint8(tvb, offset+1);

                                for (nqs_i = 0; nqs_i < nqs; nqs_i++) {
                                    for (rvpqs_i = 0; rvpqs_i < rvpqs; rvpqs_i++) {
                                        dpoe_opcode_response = proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_report_threshold, tvb, offset+2+(2*(nqs_i+rvpqs_i)), 2, ENC_BIG_ENDIAN);
                                        proto_item_append_text(dpoe_opcode_response, " (Report Threshold %i for Queue Set %i)",  nqs_i, rvpqs_i);
                                    }
                                }
                                /* This will need to be fixed for get-response, now only works for set-requests: */
                            } else if (leaf_branch == DPOE_LB_LL_FWD_STATE) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_ll_fwd_state, tvb, offset, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_S1_INT_PORT_AUTONEG) {
                                proto_tree_add_bitmask(dpoe_opcode_response_tree, tvb, offset, hf_oam_dpoe_s1_autoneg, ett_oam_dpoe_s1_autoneg, s1_autoneg_mode_bits, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_USER_PORT_OBJ) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object, tvb, offset, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_QUEUE_OBJ) {
                                dissect_oampdu_add_queue_object(dpoe_opcode_response_tree, tvb, offset);
                            } else if (leaf_branch == DPOE_LB_PORT_INGRESS_RULE) {
                                uint8_t pir_mvl;
                                pir_subtype = tvb_get_uint8(tvb, offset);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
                                switch (pir_subtype) {
                                    /* Terminator */
                                    case 0:
                                        /* no further contents */
                                        break;
                                        /* Header */
                                    case 1:
                                        proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_header_precedence, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                                        break;
                                        /* Clause */
                                    case 2:
                                        proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_clause_fc, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_clause_fi, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_clause_msbm, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_clause_lsbm, tvb, offset+4, 1, ENC_BIG_ENDIAN);
                                        proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_clause_operator, tvb, offset+5, 1, ENC_BIG_ENDIAN);
                                        event_item = proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_clause_mvl, tvb, offset+6, 1, ENC_BIG_ENDIAN);
                                        pir_mvl = tvb_get_uint8(tvb, offset+6);

                                        if (pir_mvl > 0) {
                                            proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_clause_mv, tvb, offset+7, pir_mvl, ENC_NA);
                                        } else expert_add_info_format(pinfo, event_item, &ei_oampdu_mvl_length_zero, "Match Value Field Length is Zero, Match Value Field not Decoded");

                                        break;
                                        /* Result */
                                    case 3:
                                        dpoe_opcode_response = proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr, tvb, offset+1, 1, ENC_BIG_ENDIAN);
                                        rr_byte = tvb_get_uint8(tvb, offset+1);
                                        switch (rr_byte) {
                                            case 0x00:
                                                proto_item_append_text(dpoe_opcode_response, " No operation");
                                                break;
                                            case 0x01:
                                                proto_item_append_text(dpoe_opcode_response, " Set Discard Flag for Frame");
                                                break;
                                            case 0x02:
                                                proto_item_append_text(dpoe_opcode_response, " Clear Discard Flag for Frame (Forward Frame)");
                                                break;
                                            case 0x03:
                                                proto_item_append_text(dpoe_opcode_response, " Set destination queue for frame");
                                                dissect_oampdu_add_queue_object(dpoe_opcode_response_tree, tvb, offset+2);
                                                break;
                                            case 0x04:
                                                proto_item_append_text(dpoe_opcode_response, " Set output field");
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_set_fc, tvb, offset+2, 1, ENC_BIG_ENDIAN);
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_set_fi, tvb, offset+3, 1, ENC_BIG_ENDIAN);
                                                break;
                                            case 0x05:
                                                proto_item_append_text(dpoe_opcode_response, " Copy output field");
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_copy, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                                                break;
                                            case 0x06:
                                                proto_item_append_text(dpoe_opcode_response, " Delete field");
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_delete, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                                                break;
                                            case 0x07:
                                                proto_item_append_text(dpoe_opcode_response, " Insert field");
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_insert, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                                                break;
                                            case 0x08:
                                                proto_item_append_text(dpoe_opcode_response, " Delete field and Insert current output field");
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_replace, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                                                break;
                                            case 0x09:
                                                proto_item_append_text(dpoe_opcode_response, " Do not delete field (override other Delete result)");
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_cd, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                                                break;
                                            case 0x0A:
                                                proto_item_append_text(dpoe_opcode_response, " Do not insert field (override other Insert result)");
                                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_user_port_object_result_rr_ci, tvb, offset+2, 2, ENC_BIG_ENDIAN);
                                                break;
                                            default:
                                                break;
                                        }
                                        break;
                                    default:
                                        break;
                                }
                            } else if (leaf_branch == DPOE_LB_QUEUE_CONFIG) {
                                /* "qc" is for Queue Configuration. Variable names come from CableLabs spec. */
                                uint8_t qc_n; /* number of upstream logical links */
                                uint8_t qc_m; /* number of upstream queues for link N */
                                uint8_t qc_p; /* number of downstream ports to configure */
                                uint8_t qc_j; /* number of downstream queues for port P */
                                uint8_t qc_n_i; /* iterator */
                                uint8_t qc_m_i; /* iterator */
                                uint8_t qc_p_i; /* iterator */
                                uint8_t qc_j_i; /* iterator */

                                proto_tree *dpoe_oam_qc_upstream;
                                proto_tree *dpoe_oam_qc_upstream_subtree;
                                proto_tree *dpoe_oam_qc_downstream;
                                proto_tree *dpoe_oam_qc_downstream_subtree;
                                proto_tree *dpoe_oam_qc_nq;
                                proto_tree *dpoe_oam_qc_nq_subtree;

                                qc_n = tvb_get_uint8(tvb, offset);
                                dpoe_oam_qc_upstream = proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_qc_ll_u, tvb, offset, 1, ENC_BIG_ENDIAN);
                                dpoe_oam_qc_upstream_subtree = proto_item_add_subtree(dpoe_oam_qc_upstream, ett_oam_dpoe_qc_u);
                                for (qc_n_i = 0; qc_n_i < qc_n; qc_n_i++) {

                                    offset++;
                                    qc_m = tvb_get_uint8(tvb, offset);
                                    dpoe_oam_qc_nq = proto_tree_add_item(dpoe_oam_qc_upstream_subtree, hf_oam_dpoe_qc_nq, tvb, offset, 1, ENC_BIG_ENDIAN);
                                    proto_item_append_text(dpoe_oam_qc_nq, " (Upstream link %i)", qc_n_i);
                                    dpoe_oam_qc_nq_subtree = proto_item_add_subtree(dpoe_oam_qc_nq, ett_oam_dpoe_qc_nq);
                                    for (qc_m_i = 0; qc_m_i < qc_m; qc_m_i++) {
                                        offset++;
                                        dpoe_opcode_response = proto_tree_add_item(dpoe_oam_qc_nq_subtree, hf_oam_dpoe_qc_queue_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        proto_item_append_text(dpoe_opcode_response, " (Upstream link %i queue %i size)",  qc_n_i, qc_m_i);
                                    }
                                }
                                offset++;
                                qc_p = tvb_get_uint8(tvb, offset);
                                dpoe_oam_qc_downstream = proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_qc_ports_d, tvb, offset, 1, ENC_BIG_ENDIAN);
                                dpoe_oam_qc_downstream_subtree = proto_item_add_subtree(dpoe_oam_qc_downstream, ett_oam_dpoe_qc_d);
                                for (qc_p_i = 0; qc_p_i < qc_p; qc_p_i++) {
                                    offset++;
                                    qc_j = tvb_get_uint8(tvb, offset);
                                    dpoe_oam_qc_nq = proto_tree_add_item(dpoe_oam_qc_downstream_subtree, hf_oam_dpoe_qc_nq, tvb, offset, 1, ENC_BIG_ENDIAN);
                                    proto_item_append_text(dpoe_oam_qc_nq, " (Downstream port %i)", qc_p_i);
                                    dpoe_oam_qc_nq_subtree = proto_item_add_subtree(dpoe_oam_qc_nq, ett_oam_dpoe_qc_nq);
                                    for (qc_j_i = 0; qc_j_i < qc_j; qc_j_i++) {
                                        offset++;
                                        dpoe_opcode_response = proto_tree_add_item(dpoe_oam_qc_nq_subtree, hf_oam_dpoe_qc_queue_size, tvb, offset, 1, ENC_BIG_ENDIAN);
                                        proto_item_append_text(dpoe_opcode_response, " (Downstream port %i queue %i size)",  qc_p_i, qc_j_i);
                                    }
                                }
                                /* offset variable already incremented, so variable_length should include only 1 to read next_byte */
                                variable_length = 1;
                                /* fall-through for unmatched: */
                            } else if (leaf_branch == DPOE_LB_FW_FILENAME) {
                                char *fw_filename;
                                fw_filename = tvb_get_stringzpad(pinfo->pool, tvb, offset, variable_length, ENC_ASCII);
                                proto_tree_add_string(dpoe_opcode_response_tree, hf_oam_dpoe_fw_filename, tvb, offset, variable_length, fw_filename);
                            } else if (leaf_branch == DPOE_LB_1904_1_ONU_PORT_CONFIG) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_onu_port_config_llid_count, tvb, offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_onu_port_config_uni_count, tvb, offset, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_1904_1_QUEUE_CONFIG) {
                                /* "qc" is for Queue Configuration. Variable names come from CableLabs spec. */
                                uint8_t qc_num; /* number of queues */
                                uint8_t qc_i; /* iterator */
                                proto_tree *dpoe_oam_qc_nq;
                                proto_tree *dpoe_oam_qc_nq_subtree;

                                qc_num = tvb_get_uint8(tvb, offset);
                                dpoe_oam_qc_nq = proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_qc_nq, tvb, offset, 1, ENC_BIG_ENDIAN);
                                offset += 1;
                                dpoe_oam_qc_nq_subtree = proto_item_add_subtree(dpoe_oam_qc_nq, ett_oam_dpoe_qc_nq);
                                for (qc_i = 0; qc_i < qc_num; qc_i++) {
                                    proto_tree_add_item(dpoe_oam_qc_nq_subtree, hf_oam_dpoe_1904_1_qc_queue_size, tvb, offset, 4, ENC_BIG_ENDIAN);
                                    offset += 4;
                                }
                            } else if (leaf_branch == DPOE_LB_1904_1_MAC_ENABLE_STATUS) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_mac_enable_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_1904_1_A_PHY_TYPE) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_a_phy_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_1904_1_MEDIA_AVAILABLE) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_media_available, tvb, offset, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_1904_1_AUTONEG_ADM_STATE) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_autoneg_admstate, tvb, offset, 4, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_1904_1_DUPLEX_STATUS) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_duplex_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_1904_1_MAC_CTl_FUNCTIONS) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_mac_control_functions_supported, tvb, offset, 2, ENC_BIG_ENDIAN);
                            } else if (leaf_branch == DPOE_LB_1904_1_CFG_MCAST_LLID) {
                                uint8_t action;
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_cfg_mcast_llid_action, tvb, offset, 1, ENC_BIG_ENDIAN);
                                action = tvb_get_uint8(tvb, offset);
                                switch (action) {
                                    case 0x00:
                                    case 0x01:
                                        proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_cfg_mcast_llid_value, tvb, offset+1, 2, ENC_BIG_ENDIAN);
                                        break;
                                    default:
                                        break;
                                }
                            } else if (leaf_branch == DPOE_LB_1904_1_RW_MAC_ADDRESS) {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oam_dpoe_1904_1_read_write_mac_address, tvb, offset, 6, ENC_NA);
                            } else {
                                proto_tree_add_item(dpoe_opcode_response_tree, hf_oampdu_variable_value, tvb, offset, variable_length, ENC_NA);
                            }
                        }
                        offset += variable_length;
                        next_byte = tvb_get_uint8(tvb, offset);
                    }
                    break;
                case 0x05:
                    break;
                case 0x06:
                    break;
                case 0x07:
                    break;
                case 0x08:
                    break;
                case 0x09:
                    break;
                default:
                    break;
            }
        }
    }
}

/*
 * Name: dissect_cablelabs_event_notification
 *
 * Description:
 *    This function is used to dissect the Event Notification TLVs defined in
 *    DPoE OAM v2.0 section 7.2.
 *
 *
 * Input Arguments:
 *    tvb:  buffer associated with the rcv packet (see tvbuff.h).
 *    tree: the protocol tree associated with the oampdu (see proto.h).
 *    bytes: the number of bytes of the event
 *    offset: the current offset in the buffer
 *
 * Return Values: None
 *
 */
static void
dissect_cablelabs_event_notification(tvbuff_t *tvb, proto_tree *tree, uint8_t bytes, uint32_t offset)
{
    uint32_t oui_cl = (OUI_CL_0 << 16) + (OUI_CL_1 << 8) + OUI_CL_2;
    uint32_t oui;

    proto_item *oui_item;
    proto_tree *oampdu_vendor_specific_tree;

    if (bytes >= 3) {
        oui_item = proto_tree_add_item(tree, hf_oampdu_info_oui, tvb, offset, 3, ENC_BIG_ENDIAN);
        oui = tvb_get_uint24(tvb, offset, ENC_BIG_ENDIAN);
        offset += 3;

        if (oui == oui_cl) {
            uint8_t obj_type;
            oampdu_vendor_specific_tree = proto_item_add_subtree(oui_item, ett_oampdu_vendor_specific);
            proto_tree_add_item(oampdu_vendor_specific_tree, hf_oampdu_vendor_specific_dpoe_evt_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item(oampdu_vendor_specific_tree, hf_oampdu_vendor_specific_dpoe_evt_raised, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            obj_type = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(oampdu_vendor_specific_tree, hf_oampdu_vendor_specific_dpoe_evt_object_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (obj_type == DPOE_OBJ_CTX_QUEUE) {
                proto_tree_add_item(oampdu_vendor_specific_tree, hf_oampdu_variable_value, tvb, offset, 4, ENC_NA);
            } else {
                proto_tree_add_item(oampdu_vendor_specific_tree, hf_oampdu_variable_value, tvb, offset, 2, ENC_NA);
            }
        }
    }
}

/* Register the protocol with Wireshark */
void
proto_register_oampdu(void)
{
    /* Setup list of header fields */

    static hf_register_info hf[] = {
        { &hf_oampdu_flags,
            { "Flags",    "oampdu.flags",
                FT_UINT16,    BASE_HEX,    NULL,    0x0,
                "The Flags Field", HFILL }},

        { &hf_oampdu_flags_link_fault,
            { "Link Fault",        "oampdu.flags.linkFault",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_FLAGS_LINK_FAULT,
                "The PHY detected a fault in the receive direction. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_dying_gasp,
            { "Dying Gasp",        "oampdu.flags.dyingGasp",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_FLAGS_DYING_GASP,
                "An unrecoverable local failure occurred. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_critical_event,
            { "Critical Event",        "oampdu.flags.criticalEvent",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_FLAGS_CRITICAL_EVENT,
                "A critical event has occurred. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_local_evaluating,
            { "Local Evaluating",        "oampdu.flags.localEvaluating",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_FLAGS_LOCAL_EVAL,
                "Local DTE Discovery process in progress. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_local_stable,
            { "Local Stable",        "oampdu.flags.localStable",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_FLAGS_LOCAL_STABLE,
                "Local DTE is Stable. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_remote_evaluating,
            { "Remote Evaluating",        "oampdu.flags.remoteEvaluating",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_FLAGS_REMOTE_EVAL,
                "Remote DTE Discovery process in progress. True = 1, False = 0", HFILL }},

        { &hf_oampdu_flags_remote_stable,
            { "Remote Stable",        "oampdu.flags.remoteStable",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_FLAGS_REMOTE_STABLE,
                "Remote DTE is Stable. True = 1, False = 0", HFILL }},

        { &hf_oampdu_code,
            { "OAMPDU code",    "oampdu.code",
                FT_UINT8,    BASE_HEX,    VALS(code_vals),    0x0,
                "Identifies the TLVs code", HFILL }},

        { &hf_oampdu_info_type,
            { "Type",    "oampdu.info.type",
                FT_UINT8,    BASE_HEX,    VALS(info_type_vals),    0x0,
                "Identifies the TLV type", HFILL }},

        { &hf_oampdu_info_len,
            { "TLV Length",    "oampdu.info.length",
                FT_UINT8,    BASE_DEC,    NULL,    0x0,
                "Identifies the TLVs type", HFILL }},

        { &hf_oampdu_info_version,
            { "TLV Version",    "oampdu.info.version",
                FT_UINT8,    BASE_HEX,    NULL,    0x0,
                "Identifies the TLVs version", HFILL }},

        { &hf_oampdu_info_revision,
            { "TLV Revision",    "oampdu.info.revision",
                FT_UINT16,    BASE_DEC,    NULL,    0x0,
                "Identifies the TLVs revision", HFILL }},

        { &hf_oampdu_info_state,
            { "OAM DTE States",    "oampdu.info.state",
                FT_UINT8,    BASE_HEX,    NULL,    0x0,
                "OAM DTE State of the Mux and the Parser", HFILL }},

        { &hf_oampdu_info_state_parser,
            { "Parser Action",        "oampdu.info.state.parser",
                FT_UINT8,    BASE_HEX,    VALS(parser_vals),    0x03,
                NULL, HFILL }},

        { &hf_oampdu_info_state_mux,
            { "Multiplexer Action",        "oampdu.info.state.multiplexer",
                FT_BOOLEAN,    8,        TFS(&mux),    0x04,
                NULL, HFILL }},

        { &hf_oampdu_info_oamConfig,
            { "OAM Configuration",    "oampdu.info.oamConfig",
                FT_UINT8,    BASE_HEX,    NULL,    0x0,
                NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_mode,
            { "OAM Mode",        "oampdu.info.oamConfig.mode",
                FT_BOOLEAN,    8,        TFS(&oam_mode),    OAMPDU_INFO_CONFIG_MODE,
                NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_uni,
            { "Unidirectional support",        "oampdu.flags.dyingGasp",
                FT_BOOLEAN,    8,        TFS(&oam_uni),    OAMPDU_INFO_CONFIG_UNI,
                NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_lpbk,
            { "Loopback support",        "oampdu.flags.criticalEvent",
                FT_BOOLEAN,    8,        TFS(&oam_lpbk),    OAMPDU_INFO_CONFIG_LPBK,
                NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_event,
            { "Link Events support",        "oampdu.flags.localEvaluating",
                FT_BOOLEAN,    8,        TFS(&oam_event),    OAMPDU_INFO_CONFIG_EVENT,
                NULL, HFILL }},

        { &hf_oampdu_info_oamConfig_var,
            { "Variable Retrieval",        "oampdu.flags.localStable",
                FT_BOOLEAN,    8,        TFS(&oam_var),    OAMPDU_INFO_CONFIG_VAR,
                "Variable Retrieval support", HFILL }},

        { &hf_oampdu_info_oampduConfig,
            { "Max OAMPDU Size",    "oampdu.info.oampduConfig",
                FT_UINT16,    BASE_DEC|BASE_UNIT_STRING, UNS(&units_byte_bytes),    0x0,
                "OAMPDU Configuration", HFILL }},

        { &hf_oampdu_info_oui,
            { "Organizationally Unique Identifier", "oampdu.info.oui",
                FT_UINT24,    BASE_OUI,    NULL,    0x0,
                NULL, HFILL }},

        { &hf_oampdu_info_vendor,
            { "Vendor Specific Information", "oampdu.info.vendor",
                FT_BYTES,    BASE_NONE,    NULL,    0x0,
                NULL, HFILL }},

        /*
         * Reserved for future use:
         { &hf_oampdu_info_dpoe_oam_version,
         { "DPoE OAM Version", "oampdu.info.dpoe_oam_version",
         FT_UINT8,    BASE_DEC,    NULL,    0x0,
         NULL, HFILL }},
         */
        /*
         * Event notification definitions
         */
        { &hf_oampdu_event_sequence,
            { "Sequence Number",    "oampdu.event.sequence",
                FT_UINT16,    BASE_DEC,    NULL,    0x0,
                "Identifies the Event Notification TLVs", HFILL }},

        { &hf_oampdu_event_type,
            { "Event Type",    "oampdu.event.type",
                FT_UINT8,    BASE_HEX,    VALS(event_type_vals),    0x0,
                "Identifies the TLV type", HFILL }},

        { &hf_oampdu_event_length,
            { "Event Length",    "oampdu.event.length",
                FT_UINT8,    BASE_HEX,    NULL,    0x0,
                "This field indicates the length in octets of the TLV-tuple", HFILL }},

        { &hf_oampdu_event_timeStamp,
            { "Event Timestamp (100ms)",    "oampdu.event.timestamp",
                FT_UINT16,    BASE_DEC,    NULL,    0x0,
                "Event Time Stamp in term of 100 ms intervals", HFILL }},

        /* Errored Symbol Period Event TLV */
        { &hf_oampdu_event_espeWindow,
            { "Errored Symbol Window",    "oampdu.event.espeWindow",
                FT_UINT64,    BASE_DEC,    NULL,    0x0,
                "Number of symbols in the period", HFILL }},

        { &hf_oampdu_event_espeThreshold,
            { "Errored Symbol Threshold",    "oampdu.event.espeThreshold",
                FT_UINT64,    BASE_DEC,    NULL,    0x0,
                "Number of symbols required to generate the Event", HFILL }},

        { &hf_oampdu_event_espeErrors,
            { "Errored Symbols",    "oampdu.event.espeErrors",
                FT_UINT64,    BASE_DEC,    NULL,    0x0,
                "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_espeTotalErrors,
            { "Error Running Total",    "oampdu.event.espeTotalErrors",
                FT_UINT64,    BASE_DEC,    NULL,    0x0,
                "Number of symbols in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_espeTotalEvents,
            { "Event Running Total",    "oampdu.event.espeTotalEvents",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Total Event generated since reset of the sublayer", HFILL }},

        /* Errored Frame Event TLV */
        { &hf_oampdu_event_efeWindow,
            { "Errored Frame Window",    "oampdu.event.efeWindow",
                FT_UINT16,    BASE_DEC,    NULL,    0x0,
                "Number of symbols in the period", HFILL }},

        { &hf_oampdu_event_efeThreshold,
            { "Errored Frame Threshold",    "oampdu.event.efeThreshold",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Number of frames required to generate the Event", HFILL }},

        { &hf_oampdu_event_efeErrors,
            { "Errored Frames",    "oampdu.event.efeErrors",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_efeTotalErrors,
            { "Error Running Total",    "oampdu.event.efeTotalErrors",
                FT_UINT64,    BASE_DEC,    NULL,    0x0,
                "Number of frames in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_efeTotalEvents,
            { "Event Running Total",    "oampdu.event.efeTotalEvents",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Total Event generated since reset of the sublayer", HFILL }},

        /* Errored Frame Period Event TLV */
        { &hf_oampdu_event_efpeWindow,
            { "Errored Frame Window",    "oampdu.event.efpeWindow",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Number of frame in error during the period", HFILL }},

        { &hf_oampdu_event_efpeThreshold,
            { "Errored Frame Threshold",    "oampdu.event.efpeThreshold",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Number of frames required to generate the Event", HFILL }},

        { &hf_oampdu_event_efpeErrors,
            { "Errored Frames",    "oampdu.event.efeErrors",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_efpeTotalErrors,
            { "Error Running Total",    "oampdu.event.efpeTotalErrors",
                FT_UINT64,    BASE_DEC,    NULL,    0x0,
                "Number of frames in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_efpeTotalEvents,
            { "Event Running Total",    "oampdu.event.efpeTotalEvents",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Total Event generated since reset of the sublayer", HFILL }},

        /* Errored Frame Second Summary Event TLV */
        { &hf_oampdu_event_efsseWindow,
            { "Errored Frame Window",    "oampdu.event.efsseWindow",
                FT_UINT16,    BASE_DEC,    NULL,    0x0,
                "Number of frame in error during the period", HFILL }},

        { &hf_oampdu_event_efsseThreshold,
            { "Errored Frame Threshold",    "oampdu.event.efsseThreshold",
                FT_UINT16,    BASE_DEC,    NULL,    0x0,
                "Number of frames required to generate the Event", HFILL }},

        { &hf_oampdu_event_efsseErrors,
            { "Errored Frames",    "oampdu.event.efeErrors",
                FT_UINT16,    BASE_DEC,    NULL,    0x0,
                "Number of symbols in error", HFILL }},

        { &hf_oampdu_event_efsseTotalErrors,
            { "Error Running Total",    "oampdu.event.efsseTotalErrors",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Number of frames in error since reset of the sublayer", HFILL }},

        { &hf_oampdu_event_efsseTotalEvents,
            { "Event Running Total",    "oampdu.event.efsseTotalEvents",
                FT_UINT32,    BASE_DEC,    NULL,    0x0,
                "Total Event generated since reset of the sublayer", HFILL }},

        /* Variable request and response definitions*/
        { &hf_oampdu_variable_branch,
            { "Branch",    "oampdu.variable.branch",
                FT_UINT8,    BASE_HEX,    VALS(branch_vals),    0x0,
                "Variable Branch, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_object,
            { "Leaf",    "oampdu.variable.object",
                FT_UINT16,    BASE_HEX,    VALS(object_vals),    0x0,
                "Object, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_package,
            { "Leaf",    "oampdu.variable.package",
                FT_UINT16,    BASE_HEX,    VALS(package_vals),    0x0,
                "Package, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_binding,
            { "Leaf",    "oampdu.variable.binding",
                FT_UINT16,    BASE_HEX,    VALS(binding_vals),    0x0,
                "Binding, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_attribute,
            { "Leaf",    "oampdu.variable.attribute",
                FT_UINT16,    BASE_HEX|BASE_EXT_STRING,  &attribute_vals_ext,   0x0,
                "Attribute, derived from the CMIP protocol in Annex 30A", HFILL }},

        { &hf_oampdu_variable_width,
            { "Variable Width",    "oampdu.variable.width",
                FT_UINT8,    BASE_DEC,    NULL,    0x0,
                NULL, HFILL }},

        { &hf_oampdu_variable_indication,
            { "Variable indication",    "oampdu.variable.indication",
                FT_UINT8,    BASE_HEX,    VALS(indication_vals),    0x0,
                NULL, HFILL }},

        { &hf_oampdu_variable_value,
            { "Variable Value",    "oampdu.variable.value",
                FT_BYTES,    BASE_NONE,    NULL,    0x0,
                NULL, HFILL }},

        /* Loopback Control definitions*/
        { &hf_oampdu_lpbk,
            { "Commands", "oampdu.lpbk.commands",
                FT_UINT8,    BASE_HEX,    NULL,    0x0,
                "The List of Loopback Commands", HFILL }},

        { &hf_oampdu_lpbk_enable,
            { "Enable Remote Loopback", "oampdu.lpbk.commands.enable",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_LPBK_ENABLE,
                "Enable Remote Loopback Command", HFILL }},

        { &hf_oampdu_lpbk_disable,
            { "Disable Remote Loopback", "oampdu.lpbk.commands.disable",
                FT_BOOLEAN,    8,        NULL,    OAMPDU_LPBK_DISABLE,
                "Disable Remote Loopback Command", HFILL }},

        /* Vendor-Specific definitions */
        { &hf_oampdu_vendor_specific_dpoe_opcode,
            { "DPoE Opcode", "oampdu.vendor.specific.opcode",
                FT_UINT8, BASE_HEX, VALS(vendor_specific_opcode_vals),
                0x0, NULL, HFILL }},

        { &hf_oampdu_vendor_specific_dpoe_evt_code,
            { "Event Code", "oampdu.vendor.specific.dpoe.evt.code",
                FT_UINT8, BASE_HEX, VALS(dpoe_evt_code_vals),
                0x0, NULL, HFILL }},

        { &hf_oampdu_vendor_specific_dpoe_evt_raised,
            { "Raised", "oampdu.vendor.specific.dpoe.evt.raised",
                FT_BOOLEAN, BASE_NONE, NULL,
                0x0, NULL, HFILL }},

        { &hf_oampdu_vendor_specific_dpoe_evt_object_type,
            { "Object Type", "oampdu.vendor.specific.dpoe.evt.object_type",
                FT_UINT16, BASE_HEX, VALS(dpoe_oam_object_type_vals),
                0x0, NULL, HFILL }},

        /* DPoE Variable Descriptor */
        { &hf_dpoe_variable_descriptor,
            { "Variable Descriptor", "oampdu.variable.descriptor",
                FT_UINT24, BASE_HEX, VALS(dpoe_variable_descriptor_vals),
                0x0, NULL, HFILL }},

        { &hf_dpoe_variable_response_code,
            { "Response Code", "oampdu.variable.response.code",
                FT_UINT8, BASE_HEX, VALS(dpoe_variable_response_code_vals),
                0x0, NULL, HFILL }},

        { &hf_oam_dpoe_response_eth,
            { "OAM Response Value", "oampdu.response.eth",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_oam_dpoe_response_int,
            { "OAM Response Value", "oampdu.response.int",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},

        { &hf_oam_dpoe_fw_info_boot_version,
            { "Boot Version", "oampdu.fw.boot_version",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_fw_info_boot_crc,
            { "Boot CRC", "oampdu.fw.boot_crc",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_fw_info_fw_version,
            { "FW Version", "oampdu.fw.fw_version",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_fw_info_fw_crc,
            { "FW CRC", "oampdu.fw.fw_crc",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_chipset_jedec_id,
            { "JEDEC ID", "oampdu.chipset.jedec_id",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_chipset_chip_model,
            { "Chip Model", "oampdu.chipset.chip_model",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_chipset_chip_version,
            { "Chip Version", "oampdu.chipset.chip_version",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_mll_b,
            { "Bidirectional", "oampdu.mll.b",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_mll_do,
            { "Downstream-only", "oampdu.mll.do",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_us_queues,
            { "Upstream Queues", "oampdu.pkt_buf.us_queues",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_us_queues_max_per_link,
            { "Upstream Queues Max/Link", "oampdu.pkt_buf.us_queues_max_per_link",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_us_queue_inc,
            { "Upstream Queue Increment", "oampdu.pkt_buf.us_queue_increment",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_1k), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_ds_queues,
            { "Downstream Queues", "oampdu.pkt_buf.ds_queues",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_ds_queues_max_per_link,
            { "Downstream Queues Max/Link", "oampdu.pkt_buf.ds_queues_max_per_link",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_ds_queue_inc,
            { "Downstream Queue Increment", "oampdu.pkt_buf.ds_queue_increment",
                FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_1k), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_total_memory,
            { "Total Memory", "oampdu.pkt_buf.total_memory",
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_1k), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_us_memory_max,
            { "Upstream Memory Max", "oampdu.pkt_buf.us_memory_max",
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_1k), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_pkt_buffer_ds_memory_max,
            { "Downstream Memory Max", "oampdu.pkt_buf.ds_memory_max",
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_1k), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_frame_rate_maximum,
            { "Maximum OAM Rate", "oampdu.frame.rate.min",
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_num_100ms), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_frame_rate_minimum,
            { "Minimum OAM Rate", "oampdu.frame.rate.max",
                FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_pdus_100ms), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_mfg_org_name,
            { "Mfg Organization Name", "oampdu.mfg_org_name",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_tvc_code_access_start,
            { "Code Access Start", "oampdu.tvc.code_access_start",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_tvc_cvc_access_start,
            { "CVC Access Start", "oampdu.tvc.cvc_access_start",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_vendor_name,
            { "Vendor Name", "oampdu.vendor_name",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_model_number,
            { "Model Number", "oampdu.model_number",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_hw_version,
            { "HW Version", "oampdu.hw_version",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_sw_bundle,
            { "SW Bundle", "oampdu.sw_bundle",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_mfg_info_serial_number,
            {"Serial Number", "oampdu.mfg_info.serial_number",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_mfg_info_vendor_specific,
            { "Vendor Specific", "oampdu.mfg_info.vendor_specific",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }},

        { &hf_oam_dpoe_date_of_manufacture,
            {"Date of Manufacture", "oampdu.date_of_manufacture",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_repthr_nqs,
            { "Number of Queue Sets", "oampdu.report.threshold.queue",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_repthr_rvpqs,
            { "Report Values Per Queue Set", "oampdu.report.threshold.queue.values",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_report_threshold,
            { "Report Threshold", "oampdu.report.threshold",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_ll_fwd_state,
            { "Link State", "oampdu.link_state",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg,
            { "Auto-Negotiation Capability", "oampdu.s1.autoneg",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_hd,
            { "Half Duplex", "oampdu.s1.autoneg.hd",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_fd,
            { "Full Duplex", "oampdu.s1.autoneg.fd",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_10,
            { "10 Mbps", "oampdu.s1.autoneg.10",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_100,
            { "100 Mbps", "oampdu.s1.autoneg.100",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_1000,
            { "1000 Mbps", "oampdu.s1.autoneg.1000",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0010,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_10000,
            { "10Gbps", "oampdu.s1.autoneg.10000",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0020,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_fc,
            { "Flow Control", "oampdu.s1.autoneg.fc",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0040,
                NULL, HFILL } },

        { &hf_oam_dpoe_s1_autoneg_mdi,
            { "Auto MDI/MDI-X", "oampdu.s1.autoneg.mdi",
                FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object,
            { "UNI Number", "oampdu.user.port.object",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_subtype,
            { "Subtype", "oampdu.user.port.object.subtype",
                FT_UINT16, BASE_DEC, VALS(user_port_object_subtype_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_header_precedence,
            { "Precedence", "oampdu.user.port.object.header.precedence",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_clause_fc,
            { "Field Code", "oampdu.user.port.object.clause.fc",
                FT_UINT8, BASE_HEX, VALS(user_port_object_clause_fc_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_clause_fi,
            { "Field Instance", "oampdu.user.port.object.clause.fi",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_clause_msbm,
            { "MSB Mask", "oampdu.user.port.object.clause.msbm",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_clause_lsbm,
            { "LSB Mask", "oampdu.user.port.object.clause.lsbm",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_clause_operator,
            { "Operator", "oampdu.user.port.object.clause.operator",
                FT_UINT8, BASE_HEX, VALS(user_port_object_clause_operator_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_clause_mvl,
            { "Match Value Length", "oampdu.user.port.object.clause.mvl",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_clause_mv,
            { "Match Value", "oampdu.user.port.object.clause.mv",
                FT_BYTES, SEP_SPACE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr,
            { "Rule Result", "oampdu.user.port.object.result.rr",
                FT_UINT8, BASE_HEX, VALS(user_port_object_result_rr_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_queue_obj_type,
            { "Object Type", "oampdu.user.port.object.result.rr.queue.object_type",
                FT_UINT16, BASE_HEX, VALS(dpoe_oam_object_type_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_queue_obj_inst,
            { "Object Instance", "oampdu.user.port.object.result.rr.queue.object_instance",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_queue_queue_index,
            { "Queue Number", "oampdu.user.port.object.result.rr.queue.queue_index",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_set_fc,
            { "Field Code", "oampdu.user.port.object.result.rr.set.fc",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_set_fi,
            { "Field Instance", "oampdu.user.port.object.result.rr.set.fi",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_copy,
            { "Field Code to set from field used in last clause of rule", "oampdu.user.port.object.result.rr.copy",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_delete,
            { "Field Code to remove from frame", "oampdu.user.port.object.result.rr.delete",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_insert,
            { "Field Code to insert into frame", "oampdu.user.port.object.result.rr.insert",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_replace,
            { "Field Code to replace", "oampdu.user.port.object.result.rr.replace",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_cd,
            { "Field Code not to delete", "oampdu.user.port.object.result.rr.cd",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_user_port_object_result_rr_ci,
            { "Field Code not to insert", "oampdu.user.port.object.result.rr.ci",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_qc_ll_u,
            { "Upstream Logical Links", "oampdu.queue_configuration.logical_links.upstream",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_qc_ports_d,
            { "Downstream Ports", "oampdu.queue_configuration.ports.downstream",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_qc_nq,
            {"Number of queues", "oampdu.queue_configuration.queues",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_qc_queue_size,
            {"Queue size (in 4KB units)", "oampdu.queue_configuration.size",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_fw_filename,
            {"Firmware Filename", "oampdu.fw_filename",
                FT_STRINGZ, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_onu_port_config_llid_count,
            { "LLID Count", "oampdu.onu_port.llid_count",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_onu_port_config_uni_count,
            { "UNI Count", "oampdu.onu_port.uni_count",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_mac_enable_status,
            { "MAC Enable Status", "oampdu.1904_1.mac_enable_status",
                FT_UINT8, BASE_DEC, VALS(dpoe_1904_1_mac_enable_status_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_a_phy_type,
            { "PHY Type", "oampdu.1904_1.a_phy_type",
                FT_UINT8, BASE_HEX, VALS(dpoe_1904_1_a_phy_type_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_media_available,
            { "Media Available", "oampdu.1904_1.media_available",
                FT_UINT8, BASE_DEC, VALS(dpoe_1904_1_media_available_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_autoneg_admstate,
            { "Auto-Negotiation Admin State", "oampdu.1904_1.autoneg_admstate",
                FT_UINT32, BASE_DEC, VALS(dpoe_1904_1_autoneg_admstate_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_duplex_status,
            { "Duplex Status", "oampdu.1904_1.duplex_status",
                FT_UINT8, BASE_DEC, VALS(dpoe_1904_1_duplex_status_vals), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_mac_control_functions_supported,
            { "MAC Control Functions Supported", "oampdu.1904_1.mac_control_functions_supported",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_cfg_mcast_llid_action,
            { "Config MCast LLID Action", "oampdu.1904_1.cfg_mcast_llid_action",
                FT_UINT8, BASE_DEC, VALS(dpoe_1904_1_cfg_mcast_llid_action), 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_cfg_mcast_llid_value,
            { "Config MCast LLID Value", "oampdu.1904_1.cfg_mcast_llid_value",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_read_write_mac_address,
            { "Read Write MAC Address", "oampdu.1904_1.read_write_mac_address",
                FT_ETHER, BASE_NONE, NULL, 0x0,
                NULL, HFILL } },

        { &hf_oam_dpoe_1904_1_qc_queue_size,
            { "Queue Size", "oampdu.1904_1.queue_size",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL } },

    };

    /* Setup protocol subtree array */

    static int *ett[] = {
        &ett_oampdu,
        &ett_oampdu_flags,
        &ett_oampdu_local_info,
        &ett_oampdu_local_info_state,
        &ett_oampdu_local_info_config,
        &ett_oampdu_remote_info,
        &ett_oampdu_remote_info_state,
        &ett_oampdu_remote_info_config,
        &ett_oampdu_org_info,
        &ett_oampdu_event_espe,
        &ett_oampdu_event_efe,
        &ett_oampdu_event_efpe,
        &ett_oampdu_event_efsse,
        &ett_oampdu_event_ose,
        &ett_oampdu_lpbk_ctrl,
        &ett_oampdu_vendor_specific,
        &ett_dpoe_opcode,
        &ett_dpoe_opcode_response,
        &ett_oam_dpoe_s1_autoneg,
        &ett_oam_dpoe_qc_u,
        &ett_oam_dpoe_qc_d,
        &ett_oam_dpoe_qc_nq,
    };

    static ei_register_info ei[] = {
        { &ei_oampdu_event_length_bad, { "oampdu.event.length.bad", PI_MALFORMED, PI_ERROR, "Event length should be at least 2", EXPFILL }},
        { &ei_oampdu_mvl_length_zero, { "oampdu.event.mvl.zero", PI_UNDECODED, PI_CHAT, "Match Value Field Length is Zero, Match Value Field not Decoded", EXPFILL }},
    };

    expert_module_t* expert_oampdu;

    /* Register the protocol name and description */

    proto_oampdu = proto_register_protocol("OAMPDU", "Ethernet OAM PDU", "oampdu");

    /* Required function calls to register the header fields and subtrees used */

    proto_register_field_array(proto_oampdu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_oampdu = expert_register_protocol(proto_oampdu);
    expert_register_field_array(expert_oampdu, ei, array_length(ei));

    oampdu_handle = register_dissector("oampdu", dissect_oampdu, proto_oampdu);
}

void
proto_reg_handoff_oampdu(void)
{
    dissector_add_uint("slow.subtype", OAM_SUBTYPE, oampdu_handle);
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

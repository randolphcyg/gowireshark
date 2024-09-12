/* packet-macmgmt.c
 *
 * Relevant DOCSIS specifications:
 * - DOCSIS MAC and Upper Layer Protocols Interface:
 *   - CM-SP-MULPIv4.0: https://www.cablelabs.com/specifications/CM-SP-MULPIv4.0
 *   - CM-SP-MULPIv3.1: https://www.cablelabs.com/specifications/CM-SP-MULPIv3.1
 *   - CM-SP-MULPIv3.0: https://www.cablelabs.com/specifications/CM-SP-MULPIv3.0
 *   - CM-SP-RFIv2.0  : https://www.cablelabs.com/specifications/radio-frequency-interface-specification-2
 *   - CM-SP-RFIv1.1  : https://www.cablelabs.com/specifications/radio-frequency-interface-specification
 *   - SP-RFI         : https://www.cablelabs.com/specifications/radio-frequency-interface-specification-3
 *
 * - DOCSIS Security (BPKM):
 *   - CM-SP-SECv4.0: https://www.cablelabs.com/specifications/CM-SP-SECv4.0
 *   - CM-SP-SECv3.1: https://www.cablelabs.com/specifications/CM-SP-SECv3.1
 *   - CM-SP-SECv3.0: https://www.cablelabs.com/specifications/CM-SP-SECv3.0
 *   - CM-SP-BPI+   : https://www.cablelabs.com/specifications/baseline-privacy-plus-interface-specification
 *
 * Routines for DOCSIS MAC Management Header dissection
 * Routines for Upstream Channel Change dissection
 * Routines for Ranging Message dissection
 * Routines for Registration Message dissection
 * Routines for Baseline Privacy Key Management Message dissection
 * Routines for Dynamic Service Addition Message dissection
 * Routines for Dynamic Service Change Request dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Routines for Type 2 UCD Message dissection
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Routines for Sync Message dissection
 * Routines for REG-REQ-MP dissection
 * Copyright 2007, Bruno Verstuyft  <bruno.verstuyft@excentis.com>
 *
 * Routines for DOCSIS 3.1 OFDM Channel Descriptor dissection.
 * Routines for DOCSIS 3.1 Downstream Profile Descriptor dissection.
 * Routines for Type 51 UCD - DOCSIS 3.1 only - Message dissection
 * Copyright 2016, Bruno Verstuyft <bruno.verstuyft@excentis.com>
 *
 * Routines for DCC Message dissection
 * Routines for DCD Message dissection
 * Copyright 2004, Darryl Hymel <darryl.hymel[AT]arrisi.com>
 *
 * Routines for Type 29 UCD - DOCSIS 2.0 only - Message dissection
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
 * Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
 *
 * Routines for Initial Ranging Request Message dissection
 * Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
 *
 * Routines for Baseline Privacy Key Management Attributes dissection
 * Copyright 2017, Adrian Simionov <daniel.simionov@gmail.com>
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
 *
 * Routines for MDD Message dissection
 * Copyright 2014, Adrian Simionov <adrian.simionov@arrisi.com>
 * Copyright 2007, Bruno Verstuyft <bruno.verstuyft@excentis.com>
 *
 * Routines for DOCSIS 3.0 Bonded Initial Ranging Request Message dissection.
 * Copyright 2009, Geoffrey Kimball <gekimbal[AT]cisco.com>
 *
 * Routines for Type 35 UCD - DOCSIS 3.0 only - Message dissection
 * Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
 *
 * Routines for DOCSIS 3.0 Dynamic Bonding Change Message dissection.
 * Routines for DOCSIS 3.0 DOCSIS Path Verify Message dissection.
 * Routines for DOCSIS 3.0 CM Control Message dissection.
 * Copyright 2010, Guido Reismueller <g.reismueller[AT]avm.de>
 *
 * Routines for DOCSIS 4.0 TLVs dissection
 * Copyright 2023, Andrii Vladyka <andrii.vladyka@harmonicinc.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/utf8_entities.h>
#include "packet-docsis-tlv.h"
#include <epan/addr_resolv.h>
#include <epan/asn1.h>
#include "packet-cms.h"
#include "packet-ocsp.h"
#include "packet-pkcs1.h"
#include "packet-x509af.h"
#include <epan/reassemble.h>
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/array.h>

void proto_register_docsis_mgmt(void);
void proto_reg_handoff_docsis_mgmt(void);

#define MGT_SYNC 1
#define MGT_UCD 2
#define MGT_MAP 3
#define MGT_RNG_REQ 4
#define MGT_RNG_RSP 5
#define MGT_REG_REQ 6
#define MGT_REG_RSP 7
#define MGT_UCC_REQ 8
#define MGT_UCC_RSP 9
#define MGT_TRI_TCD 10
#define MGT_TRI_TSI 11
#define MGT_BPKM_REQ 12
#define MGT_BPKM_RSP 13
#define MGT_REG_ACK 14
#define MGT_DSA_REQ 15
#define MGT_DSA_RSP 16
#define MGT_DSA_ACK 17
#define MGT_DSC_REQ 18
#define MGT_DSC_RSP 19
#define MGT_DSC_ACK 20
#define MGT_DSD_REQ 21
#define MGT_DSD_RSP 22
#define MGT_DCC_REQ 23
#define MGT_DCC_RSP 24
#define MGT_DCC_ACK 25
#define MGT_DCI_REQ 26
#define MGT_DCI_RSP 27
#define MGT_UP_DIS 28
#define MGT_TYPE29UCD 29
#define MGT_INIT_RNG_REQ 30
#define MGT_TEST_REQ 31
#define MGT_DS_CH_DESC 32
#define MGT_MDD 33
#define MGT_B_INIT_RNG_REQ 34
#define MGT_TYPE35UCD 35
#define MGT_DBC_REQ 36
#define MGT_DBC_RSP 37
#define MGT_DBC_ACK 38
#define MGT_DPV_REQ 39
#define MGT_DPV_RSP 40
#define MGT_CM_STATUS 41
#define MGT_CM_CTRL_REQ 42
#define MGT_CM_CTRL_RSP 43
#define MGT_REG_REQ_MP 44
#define MGT_REG_RSP_MP 45
#define MGT_EM_REQ 46
#define MGT_EM_RSP 47
#define MGT_CM_STATUS_ACK 48
#define MGT_OCD 49
#define MGT_DPD 50
#define MGT_TYPE51UCD 51
#define MGT_ODS_REQ 52
#define MGT_ODS_RSP 53
#define MGT_OPT_REQ 54
#define MGT_OPT_RSP 55
#define MGT_OPT_ACK 56
#define MGT_DPT_REQ 57
#define MGT_DPT_RSP 58
#define MGT_DPT_ACK 59
#define MGT_DPT_INFO 60
#define MGT_RBA_SW 61
#define MGT_RBA_HW 62
#define MGT_CWT_REQ 63
#define MGT_CWT_RSP 64
#define MGT_ECT_REQ 65
#define MGT_ECT_RSP 66
#define MGT_EXT_RNG_REQ 67
#define MGT_DPR 68
#define MGT_BPKM_REQ_V5 69
#define MGT_BPKM_RSP_V5 70

#define UCD_SYMBOL_RATE 1
#define UCD_FREQUENCY 2
#define UCD_PREAMBLE 3
#define UCD_BURST_DESCR 4
#define UCD_BURST_DESCR5 5
#define UCD_EXT_PREAMBLE 6
#define UCD_SCDMA_MODE_ENABLED 7
#define UCD_SCDMA_SPREADING_INTERVAL 8
#define UCD_SCDMA_CODES_PER_MINI_SLOT 9
#define UCD_SCDMA_ACTIVE_CODES 10
#define UCD_SCDMA_CODE_HOPPING_SEED 11
#define UCD_SCDMA_US_RATIO_NUM 12
#define UCD_SCDMA_US_RATIO_DENOM 13
#define UCD_SCDMA_TIMESTAMP_SNAPSHOT 14
#define UCD_MAINTAIN_POWER_SPECTRAL_DENSITY 15
#define UCD_RANGING_REQUIRED 16
#define UCD_MAX_SCHEDULED_CODES 17
#define UCD_RANGING_HOLD_OFF_PRIORITY_FIELD 18
#define UCD_RANGING_CHANNEL_CLASS_ID 19
#define UCD_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING 20
#define UCD_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES 21
#define UCD_HIGHER_UCD_FOR_SAME_UCID 22
#define UCD_BURST_DESCR23 23
#define UCD_CHANGE_IND_BITMASK 24
#define UCD_OFDMA_TIMESTAMP_SNAPSHOT 25
#define UCD_OFDMA_CYCLIC_PREFIX_SIZE 26
#define UCD_OFDMA_ROLLOFF_PERIOD_SIZE 27
#define UCD_SUBCARRIER_SPACING 28
#define UCD_CENTER_FREQ_SUBC_0 29
#define UCD_SUBC_EXCL_BAND 30
#define UCD_UNUSED_SUBC_SPEC 31
#define UCD_SYMB_IN_OFDMA_FRAME 32
#define UCD_RAND_SEED 33
#define EXTENDED_US_CHANNEL 34

#define UCD_MODULATION 1
#define UCD_DIFF_ENCODING 2
#define UCD_PREAMBLE_LEN 3
#define UCD_PREAMBLE_VAL_OFF 4
#define UCD_FEC 5
#define UCD_FEC_CODEWORD 6
#define UCD_SCRAMBLER_SEED 7
#define UCD_MAX_BURST 8
#define UCD_GUARD_TIME 9
#define UCD_LAST_CW_LEN 10
#define UCD_SCRAMBLER_ONOFF 11
#define UCD_RS_INT_DEPTH 12
#define UCD_RS_INT_BLOCK 13
#define UCD_PREAMBLE_TYPE 14
#define UCD_SCMDA_SCRAMBLER_ONOFF 15
#define UCD_SCDMA_CODES_PER_SUBFRAME 16
#define UCD_SCDMA_FRAMER_INT_STEP_SIZE 17
#define UCD_TCM_ENABLED 18
#define UCD_SUBC_INIT_RANG 19
#define UCD_SUBC_FINE_RANG 20
#define UCD_OFDMA_PROFILE 21
#define UCD_OFDMA_IR_POWER_CONTROL 22

#define IUC_REQUEST 1
#define IUC_REQ_DATA 2
#define IUC_INIT_MAINT 3
#define IUC_STATION_MAINT 4
#define IUC_SHORT_DATA_GRANT 5
#define IUC_LONG_DATA_GRANT 6
#define IUC_NULL_IE 7
#define IUC_DATA_ACK 8
#define IUC_ADV_PHY_SHORT_DATA_GRANT 9
#define IUC_ADV_PHY_LONG_DATA_GRANT 10
#define IUC_ADV_PHY_UGS 11
#define IUC_DATA_PROFILE_IUC12 12
#define IUC_DATA_PROFILE_IUC13 13
#define IUC_RESERVED14 14
#define IUC_EXPANSION 15

#define MAP_v1 1
#define MAP_v5 5
#define MAP_PROBE_IE_PW_MASK 0x00010000
#define MAP_PROBE_IE_ST_MASK 0x00004000

#define RNGRSP_TIMING 1
#define RNGRSP_PWR_LEVEL_ADJ 2
#define RNGRSP_OFFSET_FREQ_ADJ 3
#define RNGRSP_TRANSMIT_EQ_ADJ 4
#define RNGRSP_RANGING_STATUS 5
#define RNGRSP_DOWN_FREQ_OVER 6
#define RNGRSP_UP_CHID_OVER 7
#define RNGRSP_TRANSMIT_EQ_SET 9
#define RNGRSP_T4_TIMEOUT_MULTIPLIER 13
#define RNGRSP_DYNAMIC_RANGE_WINDOW_UPPER_EDGE 14
#define RNGRSP_TRANSMIT_EQ_ADJUST_OFDMA_CHANNELS 15
#define RNGRSP_TRANSMIT_EQ_SET_OFDMA_CHANNELS 16
#define RNGRSP_COMMANDED_POWER 17
#define RNGRSP_EXT_US_COMMANDED_POWER 18

/* Commanded Power Sub-TLVs */
#define RNGRSP_COMMANDED_POWER_DYNAMIC_RANGE_WINDOW 1
#define RNGRSP_COMMANDED_POWER_UCID_AND_POWER_LEVEL_LIST 2



/* BPKM Attributes */
#define BPKM_RESERVED 0
#define BPKM_SERIAL_NUM 1
#define BPKM_MANUFACTURER_ID 2
#define BPKM_MAC_ADDR 3
#define BPKM_RSA_PUB_KEY 4
#define BPKM_CM_ID 5
#define BPKM_DISPLAY_STR 6
#define BPKM_AUTH_KEY 7
#define BPKM_TEK 8
#define BPKM_KEY_LIFETIME 9
#define BPKM_KEY_SEQ_NUM 10
#define BPKM_HMAC_DIGEST 11
#define BPKM_SAID 12
#define BPKM_TEK_PARAM 13
#define BPKM_OBSOLETED 14
#define BPKM_CBC_IV 15
#define BPKM_ERROR_CODE 16
#define BPKM_CA_CERT 17
#define BPKM_CM_CERT 18
#define BPKM_SEC_CAPABILITIES 19
#define BPKM_CRYPTO_SUITE 20
#define BPKM_CRYPTO_SUITE_LIST 21
#define BPKM_BPI_VERSION 22
#define BPKM_SA_DESCRIPTOR 23
#define BPKM_SA_TYPE 24
#define BPKM_SA_QUERY 25
#define BPKM_SA_QUERY_TYPE 26
#define BPKM_IP_ADDRESS 27
#define BPKM_DNLD_PARAMS 28
#define BPKM_CVC_ROOT_CA_CERT 51
#define BPKM_CVC_CA_CERT 52
#define BPKM_DEV_CA_CERT 53
#define BPKM_ROOT_CA_CERT 54
#define BPKM_CM_NONCE 61
#define BPKM_MSG_SIGNATURE 62
#define BPKM_KEY_EXCHANGE_SHARE 63
#define BPKM_ALLOWED_BPI_VERSIONS 64
#define BPKM_OCSP_RSP 65
#define BPKM_CMTS_DESIGNATION 66
#define BPKM_CM_STATUS_CODE 67
#define BPKM_DETECTED_ERRORS 68
#define BPKM_VENDOR_DEFINED 127

#define DCCREQ_UP_CHAN_ID 1
#define DCCREQ_DS_PARAMS 2
#define DCCREQ_INIT_TECH 3
#define DCCREQ_UCD_SUB 4
#define DCCREQ_SAID_SUB 6
#define DCCREQ_SF_SUB 7
#define DCCREQ_CMTS_MAC_ADDR 8
#define DCCREQ_KEY_SEQ_NUM 31
#define DCCREQ_HMAC_DIGEST 27

/* Define Downstrean Parameters subtypes
 * These are subtype of DCCREQ_DS_PARAMS (2)
 */

#define DCCREQ_DS_FREQ 1
#define DCCREQ_DS_MOD_TYPE 2
#define DCCREQ_DS_SYM_RATE 3
#define DCCREQ_DS_INTLV_DEPTH 4
#define DCCREQ_DS_CHAN_ID 5
#define DCCREQ_DS_SYNC_SUB 6
#define DCCREQ_DS_OFDM_BLOCK_FREQ 7

/* Define Service Flow Substitution subtypes
 * These are subtypes of DCCREQ_SF_SUB (7)
 */
#define DCCREQ_SF_SFID 1
#define DCCREQ_SF_SID 2
#define DCCREQ_SF_UNSOL_GRANT_TREF 5

#define DCCRSP_CM_JUMP_TIME 1
#define DCCRSP_KEY_SEQ_NUM 31
#define DCCRSP_HMAC_DIGEST 27

/* Define DCC-RSP CM Jump Time subtypes
 * These are subtype of DCCRSP_CM_JUMP_TIME (1)
 */
#define DCCRSP_CM_JUMP_TIME_LENGTH 1
#define DCCRSP_CM_JUMP_TIME_START 2

#define DCCACK_KEY_SEQ_NUM 31
#define DCCACK_HMAC_DIGEST 27

#define DCD_DOWN_CLASSIFIER 23
#define DCD_DSG_RULE 50
#define DCD_DSG_CONFIG 51

/* Define Downstrean Classifier subtypes
 * These are subtype of DCD_DOWN_CLASSIFIER (23)
 */

#define DCD_CFR_ID 2
#define DCD_CFR_RULE_PRI 5
#define DCD_CFR_IP_CLASSIFIER 9

/* Define IP Classifier sub-subtypes
 * These are subtypes of DCD_CFR_IP_CLASSIFIER (23.9)
 */
#define DCD_CFR_IP_SOURCE_ADDR 3
#define DCD_CFR_IP_SOURCE_MASK 4
#define DCD_CFR_IP_DEST_ADDR 5
#define DCD_CFR_IP_DEST_MASK 6
#define DCD_CFR_TCPUDP_SRCPORT_START 7
#define DCD_CFR_TCPUDP_SRCPORT_END 8
#define DCD_CFR_TCPUDP_DSTPORT_START 9
#define DCD_CFR_TCPUDP_DSTPORT_END 10

/* Define DSG Rule subtypes
 * These are subtype of DCD_DSG_RULE (50)
 */

#define DCD_RULE_ID 1
#define DCD_RULE_PRI 2
#define DCD_RULE_UCID_RNG 3
#define DCD_RULE_CLIENT_ID 4
#define DCD_RULE_TUNL_ADDR 5
#define DCD_RULE_CFR_ID 6
#define DCD_RULE_VENDOR_SPEC 43
/* Define DSG Rule Client ID sub-subtypes
 * These are subtypes of DCD_RULE_CLIENT_ID (50.4)
 */
#define DCD_CLID_BCAST_ID 1
#define DCD_CLID_KNOWN_MAC_ADDR 2
#define DCD_CLID_CA_SYS_ID 3
#define DCD_CLID_APP_ID 4

/* Define DSG Configuration subtypes
 * These are subtype of DCD_DSG_CONFIG (51)
 */

#define DCD_CFG_CHAN_LST 1
#define DCD_CFG_TDSG1 2
#define DCD_CFG_TDSG2 3
#define DCD_CFG_TDSG3 4
#define DCD_CFG_TDSG4 5
#define DCD_CFG_VENDOR_SPEC 43

/* EM TLVs
 *
 */
#define EM_HOLDOFF_TIMER 1

/* MDD TLVs */
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST 1
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP 2
#define DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST 3
#define RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL 4
#define IP_INITIALIZATION_PARAMETERS 5
#define EARLY_AUTHENTICATION_AND_ENCRYPTION 6
#define UPSTREAM_ACTIVE_CHANNEL_LIST 7
#define UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST 8
#define UPSTREAM_FREQUENCY_RANGE 9
#define SYMBOL_CLOCK_LOCKING_INDICATOR 10
#define CM_STATUS_EVENT_CONTROL 11
#define UPSTREAM_TRANSMIT_POWER_REPORTING 12
#define DSG_DA_TO_DSID_ASSOCIATION_ENTRY 13
#define CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS 15
#define EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT 16
#define CMTS_DOCSIS_VERSION 17
#define CM_PERIODIC_MAINTENANCE_TIMEOUT_INDICATOR 18
#define DLS_BROADCAST_AND_MULTICAST_DELIVERY_METHOD 19
#define CM_STATUS_EVENT_ENABLE_FOR_DOCSIS_3_1_EVENTS 20
#define DIPLEXER_BAND_EDGE 21
#define ADVANCED_BAND_PLAN 22
#define MDD_BPI_PLUS 23


/* Downstream Active Channel List */
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID 1
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY 2
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX 3
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE 4
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK 5
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR 6
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS 7
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_FDX_SUB_BAND_ID 8
#define DOWNSTREAM_ACTIVE_CHANNEL_LIST_FDX_DS 9

/* MAC Domain Downstream Service Group */
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER 1
#define MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS 2

/* Modulation Orders */
#define QAM64 0
#define QAM256 1

/* Annexes */
#define J83_ANNEX_A 0
#define J83_ANNEX_B 1
#define J83_ANNEX_C 2

/* Primary Capable */
#define NOT_PRIMARY_CAPABLE 0
#define PRIMARY_CAPABLE 1

/* Can carry MAP and UCD */
#define CANNOT_CARRY_MAP_UCD 0
#define CAN_CARRY_MAP_UCD 1

/* Receive Channel Profile Reporting Control */
#define RCP_CENTER_FREQUENCY_SPACING 1
#define VERBOSE_RCP_REPORTING 2
#define FRAGMENTED_RCP_TRANSMISSION 3

/* Frequency spacing */
#define ASSUME_6MHZ_CENTER_FREQUENCY_SPACING 0
#define ASSUME_8MHZ_CENTER_FREQUENCY_SPACING 1

/* Verbose RCP reporting */
#define RCP_NO_VERBOSE_REPORTING 0
#define RCP_VERBOSE_REPORTING 1

/* Sub-TLVs for IP Initialization Parameters */
#define IP_PROVISIONING_MODE 1
#define PRE_REGISTRATION_DSID 2

/* IP Provisioning Modes */
#define IPv4_ONLY 0
#define IPv6_ONLY 1
#define IP_ALTERNATE 2
#define DUAL_STACK 3

/* Early authentication and encryption */
#define EAE_DISABLED 0
#define EAE_ENABLED 1

/* Upstream Active Channel List */
#define UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID 1
#define UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK 2
#define UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_PRIORITY 3
#define UPSTREAM_ACTIVE_CHANNEL_LIST_DSCHIDS_MAPS_UCDS 4
#define UPSTREAM_ACTIVE_CHANNEL_LIST_FDX_UPSTREAM_CHANNEL 5
#define UPSTREAM_ACTIVE_CHANNEL_LIST_FDX_SUBBAND_ID 6

/* Upstream Frequency Range */
#define STANDARD_UPSTREAM_FREQUENCY_RANGE 0
#define EXTENDED_UPSTREAM_FREQUENCY_RANGE 1

/* Symbol Clock Locking Indicator */
#define NOT_LOCKED_TO_MASTER_CLOCK 0
#define LOCKED_TO_MASTER_CLOCK 1

/* CM-STATUS Event Control */
#define EVENT_TYPE_CODE 1
#define MAXIMUM_EVENT_HOLDOFF_TIMER 2
#define MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT 3

/* CM-STATUS Events */
#define SECONDARY_CHANNEL_MDD_TIMEOUT 1
#define QAM_FEC_LOCK_FAILURE 2
#define SEQUENCE_OUT_OF_RANGE 3
#define MDD_RECOVERY 4
#define QAM_FEC_LOCK_RECOVERY 5
#define T4_TIMEOUT 6
#define T3_RETRIES_EXCEEDED 7
#define SUCCESFUL_RANGING_AFTER_T3_RETRIES_EXCEEDED 8
#define CM_OPERATING_ON_BATTERY_BACKUP 9
#define CM_RETURNED_TO_AC_POWER 10
#define MAC_REMOVAL_EVENT 11
#define DS_OFDM_PROFILE_FAILURE 16
#define PRIMARY_DS_CHANGE 17
#define DPD_MISMATCH 18
#define DEPRECATED 19
#define NCP_PROFILE_FAILURE 20
#define PLC_FAILURE 21
#define NCP_PROFILE_RECOVERY 22
#define PLC_RECOVERY 23
#define OFDM_PROFILE_RECOVERY 24
#define OFDMA_FAILURE 25
#define MAP_STORAGE_OVERFLOW 26
#define MAP_STORAGE_ALMOST_FULL 27

/* Upstream Transmit Power Reporting */
#define CM_DOESNT_REPORT_TRANSMIT_POWER 0
#define CM_REPORTS_TRANSMIT_POWER 1

/* DSG DA to DSID association entry */
#define DSG_DA_TO_DSID_ASSOCIATION_DA 1
#define DSG_DA_TO_DSID_ASSOCIATION_DSID 2

/* CMTS DOCSIS VERSION */
#define CMTS_DOCSIS_VERSION_MAJOR_PRE_40 1
#define CMTS_DOCSIS_VERSION_MINOR_PRE_40 2
#define CMTS_DOCSIS_VERSION_MAJOR 3
#define CMTS_DOCSIS_VERSION_MINOR 4
#define CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE 5
#define CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE_FDD 0x01
#define CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE_FDX 0x02

/* Define Tukey raised cosine window */
#define TUKEY_0TS 0
#define TUKEY_64TS 1
#define TUKEY_128TS 2
#define TUKEY_192TS 3
#define TUKEY_256TS 4

/* Define Cyclic prefix */
#define CYCLIC_PREFIX_192_TS 0
#define CYCLIC_PREFIX_256_TS 1
#define CYCLIC_PREFIX_512_TS 2
#define CYCLIC_PREFIX_768_TS 3
#define CYCLIC_PREFIX_1024_TS 4

/* Define Sub carrier spacing */
#define SPACING_25KHZ 0
#define SPACING_50KHZ 1

#define SEC_CH_MDD_TIMEOUT 1
#define QAM_FEC_LOCK_FAILURE 2
#define SEQ_OUT_OF_RANGE 3
#define SEC_CH_MDD_RECOVERY 4
#define QAM_FEC_LOCK_RECOVERY 5
#define T4_TIMEOUT 6
#define T3_RETRIES_EXCEEDED 7
#define SUCCESS_RANGING_AFTER_T3_RETRIES_EXCEEDED 8
#define CM_ON_BATTERY 9
#define CM_ON_AC_POWER 10
#define MAC_REMOVAL_EVENT 11
#define DS_OFDM_PROFILE_FAILURE 16
#define PRIMARY_DOWNSTREAM_CHANGE 17
#define DPD_MISMATCH 18
#define NCP_PROFILE_FAILURE 20
#define PLC_FAILURE 21
#define NCP_PROFILE_RECOVERY 22
#define PLC_RECOVERY 23
#define OFDM_PROFILE_RECOVERY 24
#define OFDMA_PROFILE_FAILURE 25
#define MAP_STORAGE_OVERFLOW_INDICATOR 26
#define MAP_STORAGE_ALMOST_FULL_INDICATOR 27

#define STATUS_EVENT 1

#define EVENT_DESCR 2
#define EVENT_DS_CH_ID 4
#define EVENT_US_CH_ID 5
#define EVENT_DSID 6
#define EVENT_MAC_ADDRESS 7
#define EVENT_DS_OFDM_PROFILE_ID 8
#define EVENT_US_OFDMA_PROFILE_ID 9

#define CM_CTRL_MUTE 1
#define CM_CTRL_MUTE_TIMEOUT 2
#define CM_CTRL_REINIT 3
#define CM_CTRL_DISABLE_FWD 4
#define CM_CTRL_DS_EVENT 5
#define CM_CTRL_US_EVENT 6
#define CM_CTRL_EVENT 7

#define DS_EVENT_CH_ID 1
#define DS_EVENT_MASK 2

#define US_EVENT_CH_ID 1
#define US_EVENT_MASK 2

/* OCD */
#define DISCRETE_FOURIER_TRANSFORM_SIZE 0
#define CYCLIC_PREFIX 1
#define ROLL_OFF 2
#define OFDM_SPECTRUM_LOCATION 3
#define TIME_INTERLEAVING_DEPTH 4
#define SUBCARRIER_ASSIGNMENT_RANGE_LIST 5
#define PRIMARY_CAPABILITY_INDICATOR 6
#define FDX_INDICATOR 7

/* DPD */
#define SUBCARRIER_ASSIGNMENT_VECTOR 6

#define SUBCARRIER_ASSIGNMENT_RANGE_CONT 0
#define SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1 1
#define SUBCARRIER_ASSIGNMENT_LIST 2

#define OPT_REQ_REQ_STAT 1
#define OPT_REQ_RXMER_THRESH_PARAMS 2
#define OPT_REQ_RXMER_THRESH_PARAMS_MODULATION_ORDER 1
#define OPT_REQ_TRIGGER_DEFINITION 7
#define OPT_REQ_TRIGGER_DEFINITION_TRIGGER_TYPE 1
#define OPT_REQ_TRIGGER_DEFINITION_MEASUREMENT_DURATION 2
#define OPT_REQ_TRIGGER_DEFINITION_TRIGGERING_SID 3
#define OPT_REQ_TRIGGER_DEFINITION_US_CHANNEL_ID 4
#define OPT_REQ_TRIGGER_DEFINITION_OUDP_SOUND_AMBIG_OFFSET 5
#define OPT_REQ_TRIGGER_DEFINITION_RXMER_TO_REPORT 6
#define OPT_REQ_TRIGGER_DEFINITION_START_TIME 7

#define OPT_RSP_RXMER 1
#define OPT_RSP_DATA_CW 2
#define OPT_RSP_NCP_FIELDS 3

#define OPT_RSP_RXMER_SUBCARRIER 1
#define OPT_RSP_RXMER_SUBCARRIER_THRESHOLD 2
#define OPT_RSP_RXMER_SUBCARRIER_THRESHOLD_COUNT 3
#define OPT_RSP_RXMER_SNR_MARGIN 4
#define OPT_RSP_RXMER_AVG 5
#define OPT_RSP_RXMER_ECT_RBA_SUBBAND_DIRECTION 6

#define OPT_RSP_DATA_CW_COUNT 1
#define OPT_RSP_DATA_CW_CORRECTED 2
#define OPT_RSP_DATA_CW_UNCORRECTABLE 3
#define OPT_RSP_DATA_CW_THRESHOLD_COMPARISON 4

#define OPT_RSP_NCP_FIELDS_COUNT 1
#define OPT_RSP_NCP_FIELDS_FAILURE 2
#define OPT_RSP_NCP_FIELDS_THRESHOLD_COMPARISON 3

#define DIPLEXER_US_UPPER_BAND_EDGE 1
#define DIPLEXER_DS_LOWER_BAND_EDGE 2
#define DIPLEXER_DS_UPPER_BAND_EDGE 3
#define DIPLEXER_US_UPPER_BAND_EDGE_OVERRIDE 4
#define DIPLEXER_DS_LOWER_BAND_EDGE_OVERRIDE 5
#define DIPLEXER_DS_UPPER_BAND_EDGE_OVERRIDE 6

/* MDD Advanced Band Plan */
#define MDD_ABP_SUB_BAND_COUNT 2
#define MDD_ABP_SUB_BAND_WIDTH 3

/* MDD BPI+ */
#define MDD_BPI_PLUS_VERSION 1
#define MDD_BPI_PLUS_CFG 2

#define KEY_MGMT_VERSION 0
#define KEY_MGMT_MULTIPART 1

/* CWT-REQ and CWT-RSP */
#define CWT_PHASE_ROTATION 1
#define CWT_MAX_DURATION 2
#define CWT_US_ENCODINGS 3
#define CWT_US_ENCODINGS_CID 1
#define CWT_US_ENCODINGS_SC_INDEX 2
#define CWT_US_ENCODINGS_POWER_BOOST 3

/* ECT-REQ and ECT-RSP */
#define ECT_CONTROL 87
#define ECT_CONTROL_SUBBAND_DIRECTION 1
#define ECT_CONTROL_STATUS 2
#define ECT_CONTROL_METHOD 3
#define ECT_CONTROL_METHOD_FG 1
#define ECT_CONTROL_METHOD_FG_DURATION 1
#define ECT_CONTROL_METHOD_FG_PERIODICITY 2
#define ECT_CONTROL_METHOD_FG_EXPIRATION_TIME 3
#define ECT_CONTROL_METHOD_FG_DS_ZBL 4
#define ECT_CONTROL_METHOD_BG 2
#define ECT_CONTROL_METHOD_BG_DURATION 1
#define ECT_CONTROL_METHOD_BG_PERIODICITY 2
#define ECT_CONTROL_METHOD_BG_EXPIRATION_TIME 3
#define ECT_CONTROL_METHOD_BG_START_TIME 4
#define ECT_CONTROL_PARTIAL_SERVICE 4
#define ECT_CONTROL_PARTIAL_SERVICE_DCID 1
#define ECT_CONTROL_PARTIAL_SERVICE_UCID 2
#define ECT_CONTROL_DEFERRAL_TIME 5
#define ECT_CONTROL_RXMER_DURATION 6

/* BPKM CMTS Designation */
#define BPKMATTR_CMTS_DESIGNATION_CERTIFICATE_FINGERPRINT 0
#define BPKMATTR_CMTS_DESIGNATION_COMMON_NAME 1
#define BPKMATTR_CMTS_DESIGNATION_ORG_UNIT 2
#define BPKMATTR_CMTS_DESIGNATION_ORG_NAME 3
#define BPKMATTR_CMTS_DESIGNATION_SERIAL_NUMBER 4
#define BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_FINGERPRINT 5
#define BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_COMMON_NAME 6
#define BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_ORG_UNIT 7
#define BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_ORG_NAME 8
#define BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_SERIAL_NUMBER 9

static int proto_docsis_mgmt;
static int proto_docsis_sync;
static int proto_docsis_ucd;
static int proto_docsis_map_v1;
static int proto_docsis_map_v5;
static int proto_docsis_rngreq;
static int proto_docsis_rngrsp;
static int proto_docsis_regreq;
static int proto_docsis_regrsp;
static int proto_docsis_uccreq;
static int proto_docsis_uccrsp;
static int proto_docsis_bpkmreq;
static int proto_docsis_bpkmrsp;
static int proto_docsis_regack;
static int proto_docsis_dsareq;
static int proto_docsis_dsarsp;
static int proto_docsis_dsaack;
static int proto_docsis_dscreq;
static int proto_docsis_dscrsp;
static int proto_docsis_dscack;
static int proto_docsis_dsdreq;
static int proto_docsis_dsdrsp;
static int proto_docsis_dccreq;
static int proto_docsis_dccrsp;
static int proto_docsis_dccack;
static int proto_docsis_type29ucd;
static int proto_docsis_intrngreq;
static int proto_docsis_dcd;
static int proto_docsis_mdd;
static int proto_docsis_bintrngreq;
static int proto_docsis_type35ucd;
static int proto_docsis_dbcreq;
static int proto_docsis_dbcrsp;
static int proto_docsis_dbcack;
static int proto_docsis_dpvreq;
static int proto_docsis_dpvrsp;
static int proto_docsis_cmstatus;
static int proto_docsis_cmstatusack;
static int proto_docsis_cmctrlreq;
static int proto_docsis_cmctrlrsp;
static int proto_docsis_regreqmp;
static int proto_docsis_regrspmp;
static int proto_docsis_emreq;
static int proto_docsis_emrsp;
static int proto_docsis_ocd;
static int proto_docsis_dpd;
static int proto_docsis_type51ucd;
static int proto_docsis_optreq;
static int proto_docsis_optrsp;
static int proto_docsis_optack;
static int proto_docsis_rba;
static int proto_docsis_cwt_req;
static int proto_docsis_cwt_rsp;
static int proto_docsis_ect_req;
static int proto_docsis_ect_rsp;
static int proto_docsis_ext_rngreq;
static int proto_docsis_dpr;

static int hf_docsis_sync_cmts_timestamp;

static int hf_docsis_ucd_config_ch_cnt;
static int hf_docsis_ucd_mini_slot_size;
static int hf_docsis_ucd_type;
static int hf_docsis_ucd_length;
static int hf_docsis_ucd_burst_type;
static int hf_docsis_ucd_burst_length;
static int hf_docsis_ucd_symbol_rate;
static int hf_docsis_ucd_frequency;
static int hf_docsis_ucd_preamble_pat;
static int hf_docsis_ucd_ext_preamble_pat;
static int hf_docsis_ucd_scdma_mode_enabled;
static int hf_docsis_ucd_scdma_spreading_interval;
static int hf_docsis_ucd_scdma_codes_per_mini_slot;
static int hf_docsis_ucd_scdma_active_codes;
static int hf_docsis_ucd_scdma_code_hopping_seed;
static int hf_docsis_ucd_scdma_us_ratio_num;
static int hf_docsis_ucd_scdma_us_ratio_denom;
static int hf_docsis_ucd_scdma_timestamp_snapshot;
static int hf_docsis_ucd_maintain_power_spectral_density;
static int hf_docsis_ucd_ranging_required;
static int hf_docsis_ucd_max_scheduled_codes;
static int hf_docsis_ucd_rnghoff_cm;
static int hf_docsis_ucd_rnghoff_erouter;
static int hf_docsis_ucd_rnghoff_emta;
static int hf_docsis_ucd_rnghoff_estb;
static int hf_docsis_ucd_rnghoff_rsvd;
static int hf_docsis_ucd_rnghoff_id_ext;
static int hf_docsis_ucd_chan_class_id_cm;
static int hf_docsis_ucd_chan_class_id_erouter;
static int hf_docsis_ucd_chan_class_id_emta;
static int hf_docsis_ucd_chan_class_id_estb;
static int hf_docsis_ucd_chan_class_id_rsvd;
static int hf_docsis_ucd_chan_class_id_id_ext;
static int hf_docsis_ucd_scdma_scrambler_onoff;
static int hf_docsis_ucd_scdma_codes_per_subframe;
static int hf_docsis_ucd_scdma_framer_int_step_size;
static int hf_docsis_ucd_tcm_enabled;
static int hf_docsis_ucd_active_code_hopping;
static int hf_docsis_ucd_higher_ucd_for_same_ucid;
static int hf_docsis_ucd_higher_ucd_for_same_ucid_resv;
static int hf_docsis_ucd_scdma_selection_active_codes;
static int hf_docsis_ucd_iuc;
static int hf_docsis_ucd_change_ind_bitmask_subc_excl_band;
static int hf_docsis_ucd_change_ind_bitmask_unused_subc;
static int hf_docsis_ucd_change_ind_bitmask_other_subc;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc5;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc6;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc9;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc10;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc11;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc12;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc13;
static int hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc3_or_4;
static int hf_docsis_ucd_change_ind_bitmask_reserved;
static int hf_docsis_ucd_ofdma_timestamp_snapshot;
static int hf_docsis_ucd_ofdma_timestamp_snapshot_reserved;
static int hf_docsis_ucd_ofdma_timestamp_snapshot_d30timestamp;
static int hf_docsis_ucd_ofdma_timestamp_snapshot_4msbits_of_div20;
static int hf_docsis_ucd_ofdma_timestamp_snapshot_minislot_count;
static int hf_docsis_ucd_ofdma_cyclic_prefix_size;
static int hf_docsis_ucd_ofdma_rolloff_period_size;
static int hf_docsis_ucd_subc_spacing;
static int hf_docsis_ucd_cent_freq_subc0;
static int hf_docsis_ucd_subcarrier_range;
static int hf_docsis_ucd_symb_ofdma_frame;
static int hf_docsis_ucd_rand_seed;
static int hf_docsis_ucd_extended_us_channel;

static int hf_docsis_burst_mod_type;
static int hf_docsis_burst_diff_encoding;
static int hf_docsis_burst_preamble_len;
static int hf_docsis_burst_preamble_val_off;
static int hf_docsis_burst_fec;
static int hf_docsis_burst_fec_codeword;
static int hf_docsis_burst_scrambler_seed;
static int hf_docsis_burst_max_burst;
static int hf_docsis_burst_guard_time;
static int hf_docsis_burst_last_cw_len;
static int hf_docsis_burst_scrambler_onoff;
static int hf_docsis_rs_int_depth;
static int hf_docsis_rs_int_block;
static int hf_docsis_preamble_type;
static int hf_docsis_subc_init_rang;
static int hf_docsis_subc_fine_rang;
static int hf_docsis_ofdma_prof_mod_order;
static int hf_docsis_ofdma_prof_pilot_pattern;
static int hf_docsis_ofdma_prof_num_add_minislots;
static int hf_docsis_ofdma_ir_pow_ctrl_start_pow;
static int hf_docsis_ofdma_ir_pow_ctrl_step_size;

static int hf_docsis_map_ucd_count;
static int hf_docsis_map_numie;
static int hf_docsis_map_numie_v5;
static int hf_docsis_map_alloc_start;
static int hf_docsis_map_ack_time;
static int hf_docsis_map_rng_start;
static int hf_docsis_map_rng_end;
static int hf_docsis_map_data_start;
static int hf_docsis_map_data_end;
static int hf_docsis_map_ie;
static int hf_docsis_map_probe_ie;

static int hf_docsis_map_rsvd;
static int hf_docsis_map_rsvd_v5;
static int hf_docsis_map_cat;

static int hf_docsis_map_sid;
static int hf_docsis_map_iuc;
static int hf_docsis_map_offset;
static int hf_docsis_map_mer;
static int hf_docsis_map_pw;
static int hf_docsis_map_eq;
static int hf_docsis_map_st;
static int hf_docsis_map_probe_frame;
static int hf_docsis_map_symbol_in_frame;
static int hf_docsis_map_start_subc;
static int hf_docsis_map_subc_skip;
static int hf_docsis_map_ect;


static int hf_docsis_rngreq_sid_field_bit15;
static int hf_docsis_rngreq_sid_field_bit14;
static int hf_docsis_rngreq_sid_field_bit15_14;
static int hf_docsis_rngreq_sid;
static int hf_docsis_rngreq_pend_compl;

static int hf_docsis_rngrsp_type;
static int hf_docsis_rngrsp_length;
static int hf_docsis_rngrsp_sid;
static int hf_docsis_rngrsp_timing_adj;
static int hf_docsis_rngrsp_power_adj;
static int hf_docsis_rngrsp_freq_adj;
static int hf_docsis_rngrsp_xmit_eq_adj;
static int hf_docsis_rngrsp_ranging_status;
static int hf_docsis_rngrsp_down_freq_over;
static int hf_docsis_rngrsp_upstream_ch_over;
static int hf_docsis_rngrsp_xmit_eq_set;
static int hf_docsis_rngrsp_rngrsp_t4_timeout_multiplier;
static int hf_docsis_rngrsp_dynamic_range_window_upper_edge;
static int hf_docsis_rngrsp_tlv_unknown;
static int hf_docsis_rngrsp_trans_eq_data;
static int hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_main_tap_location;
static int hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_number_of_forward_taps_per_symbol;
static int hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_number_of_forward_taps_n;
static int hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_reserved;
static int hf_docsis_rngrsp_trans_eq_enc_lowest_subc;
static int hf_docsis_rngrsp_trans_eq_enc_highest_subc;
static int hf_docsis_rngrsp_trans_eq_enc_coef_real;
static int hf_docsis_rngrsp_trans_eq_enc_coef_imag;
static int hf_docsis_rngrsp_commanded_power_data;
static int hf_docsis_rngrsp_commanded_power_dynamic_range_window;
static int hf_docsis_rngrsp_commanded_power_ucid;
static int hf_docsis_rngrsp_commanded_power_trans_pow_lvl;


static int hf_docsis_regreq_sid;
static int hf_docsis_regrsp_sid;
static int hf_docsis_regrsp_response;

static int hf_docsis_bpkm_code;
static int hf_docsis_bpkm_length;
static int hf_docsis_bpkm_ident;
static int hf_docsis_bpkmattr;
static int hf_docsis_bpkmattr_tlv;
static int hf_docsis_bpkmattr_tlv_type;
static int hf_docsis_bpkmattr_tlv_length;
static int hf_docsis_bpkmattr_serial_num;
static int hf_docsis_bpkmattr_manf_id;
static int hf_docsis_bpkmattr_mac_addr;
static int hf_docsis_bpkmattr_rsa_pub_key;
static int hf_docsis_bpkmattr_cm_id;
static int hf_docsis_bpkmattr_display_str;
static int hf_docsis_bpkmattr_auth_key;
static int hf_docsis_bpkmattr_tek;
static int hf_docsis_bpkmattr_key_life;
static int hf_docsis_bpkmattr_key_seq;
static int hf_docsis_bpkmattr_hmac_digest;
static int hf_docsis_bpkmattr_said;
static int hf_docsis_bpkmattr_tek_params;
static int hf_docsis_bpkmattr_cbc_iv;
static int hf_docsis_bpkmattr_error_code;
static int hf_docsis_bpkmattr_ca_cert;
static int hf_docsis_bpkmattr_cm_cert;
static int hf_docsis_bpkmattr_security_cap;
static int hf_docsis_bpkmattr_crypto_suite;
static int hf_docsis_bpkmattr_crypto_suite_encr;
static int hf_docsis_bpkmattr_crypto_suite_auth;
static int hf_docsis_bpkmattr_crypto_suite_list;
static int hf_docsis_bpkmattr_bpi_version;
static int hf_docsis_bpkmattr_sa_descr;
static int hf_docsis_bpkmattr_sa_type;
static int hf_docsis_bpkmattr_sa_query;
static int hf_docsis_bpkmattr_sa_query_type;
static int hf_docsis_bpkmattr_ip_address;
static int hf_docsis_bpkmattr_download_param;
static int hf_docsis_bpkmattr_cvc_root_ca_cert;
static int hf_docsis_bpkmattr_cvc_ca_cert;
static int hf_docsis_bpkmattr_dev_ca_cert;
static int hf_docsis_bpkmattr_root_ca_cert;
static int hf_docsis_bpkmattr_cm_nonce;
static int hf_docsis_bpkmattr_msg_signature;
static int hf_docsis_bpkmattr_key_exchange_share_field_id;
static int hf_docsis_bpkmattr_key_exchange_share_key_share;
static int hf_docsis_bpkmattr_allowed_bpi_versions;
static int hf_docsis_bpkmattr_allowed_bpi_version;
static int hf_docsis_bpkmattr_ocsp_responses;
static int hf_docsis_bpkmattr_ocsp_response;
static int hf_docsis_bpkmattr_cmts_designation;
static int hf_docsis_bpkmattr_cmts_designation_data_type;
static int hf_docsis_bpkmattr_cmts_designation_certificate_fingerprint;
static int hf_docsis_bpkmattr_cmts_designation_common_name;
static int hf_docsis_bpkmattr_cmts_designation_org_unit;
static int hf_docsis_bpkmattr_cmts_designation_org_name;
static int hf_docsis_bpkmattr_cmts_designation_serial_number;
static int hf_docsis_bpkmattr_cmts_designation_issuing_ca_fingerprint;
static int hf_docsis_bpkmattr_cmts_designation_issuing_ca_common_name;
static int hf_docsis_bpkmattr_cmts_designation_issuing_ca_org_unit;
static int hf_docsis_bpkmattr_cmts_designation_issuing_ca_org_name;
static int hf_docsis_bpkmattr_cmts_designation_issuing_ca_serial_number;
static int hf_docsis_bpkmattr_cm_status_code;
static int hf_docsis_bpkmattr_detected_errors;
static int hf_docsis_bpkmattr_vendor_def;

static int hf_docsis_regack_sid;
static int hf_docsis_regack_response;

static int hf_docsis_dsarsp_response;
static int hf_docsis_dsaack_response;

static int hf_docsis_dscrsp_response;
static int hf_docsis_dscack_response;

static int hf_docsis_dsdreq_rsvd;
static int hf_docsis_dsdreq_sfid;

static int hf_docsis_dsdrsp_confcode;
static int hf_docsis_dsdrsp_rsvd;

static int hf_docsis_dccreq_type;
static int hf_docsis_dccreq_length;
static int hf_docsis_dccreq_tran_id;
static int hf_docsis_dccreq_up_chan_id;
static int hf_docsis_dcc_ds_params_subtype;
static int hf_docsis_dcc_ds_params_length;
static int hf_docsis_dccreq_ds_freq;
static int hf_docsis_dccreq_ds_mod_type;
static int hf_docsis_dccreq_ds_sym_rate;
static int hf_docsis_dccreq_ds_intlv_depth_i;
static int hf_docsis_dccreq_ds_intlv_depth_j;
static int hf_docsis_dccreq_ds_chan_id;
static int hf_docsis_dccreq_ds_sync_sub;
static int hf_docsis_dccreq_ds_ofdm_block_freq;
static int hf_docsis_dccreq_init_tech;
static int hf_docsis_dccreq_ucd_sub;
static int hf_docsis_dccreq_said_sub_cur;
static int hf_docsis_dccreq_said_sub_new;
static int hf_docsis_dcc_sf_sub_subtype;
static int hf_docsis_dcc_sf_sub_length;
static int hf_docsis_dccreq_sf_sfid_cur;
static int hf_docsis_dccreq_sf_sfid_new;
static int hf_docsis_dccreq_sf_sid_cur;
static int hf_docsis_dccreq_sf_sid_new;
static int hf_docsis_dccreq_sf_unsol_grant_tref;
static int hf_docsis_dccreq_cmts_mac_addr;
static int hf_docsis_dccreq_key_seq_num;
static int hf_docsis_dccreq_hmac_digest;
static int hf_docsis_dccrsp_conf_code;
static int hf_docsis_dccrsp_type;
static int hf_docsis_dccrsp_length;
static int hf_docsis_dcc_cm_jump_subtype;
static int hf_docsis_dcc_cm_jump_length;
static int hf_docsis_dccrsp_cm_jump_time_length;
static int hf_docsis_dccrsp_cm_jump_time_start;
static int hf_docsis_dccrsp_key_seq_num;
static int hf_docsis_dccrsp_hmac_digest;
static int hf_docsis_dccack_type;
static int hf_docsis_dccack_length;
static int hf_docsis_dccack_key_seq_num;
static int hf_docsis_dccack_hmac_digest;

static int hf_docsis_intrngreq_sid;

static int hf_docsis_dcd_config_ch_cnt;
static int hf_docsis_dcd_num_of_frag;
static int hf_docsis_dcd_frag_sequence_num;
static int hf_docsis_dcd_type;
static int hf_docsis_dcd_length;
static int hf_docsis_dcd_down_classifier_subtype;
static int hf_docsis_dcd_down_classifier_length;
static int hf_docsis_dcd_cfr_id;
static int hf_docsis_dcd_cfr_rule_pri;
static int hf_docsis_dcd_cfr_ip_subtype;
static int hf_docsis_dcd_cfr_ip_length;
static int hf_docsis_dcd_cfr_ip_source_addr;
static int hf_docsis_dcd_cfr_ip_source_mask;
static int hf_docsis_dcd_cfr_ip_dest_addr;
static int hf_docsis_dcd_cfr_ip_dest_mask;
static int hf_docsis_dcd_cfr_tcpudp_srcport_start;
static int hf_docsis_dcd_cfr_tcpudp_srcport_end;
static int hf_docsis_dcd_cfr_tcpudp_dstport_start;
static int hf_docsis_dcd_cfr_tcpudp_dstport_end;
static int hf_docsis_dcd_rule_id;
static int hf_docsis_dcd_rule_pri;
static int hf_docsis_dcd_rule_ucid_list;
static int hf_docsis_dcd_clid_subtype;
static int hf_docsis_dcd_clid_length;
static int hf_docsis_dcd_clid_bcast_id;
static int hf_docsis_dcd_clid_known_mac_addr;
static int hf_docsis_dcd_clid_ca_sys_id;
static int hf_docsis_dcd_clid_app_id;
static int hf_docsis_dcd_dsg_rule_subtype;
static int hf_docsis_dcd_dsg_rule_length;
static int hf_docsis_dcd_rule_tunl_addr;
static int hf_docsis_dcd_rule_cfr_id;
static int hf_docsis_dcd_rule_vendor_spec;
static int hf_docsis_dcd_cfg_subtype;
static int hf_docsis_dcd_cfg_length;
static int hf_docsis_dcd_cfg_chan;
static int hf_docsis_dcd_cfg_tdsg1;
static int hf_docsis_dcd_cfg_tdsg2;
static int hf_docsis_dcd_cfg_tdsg3;
static int hf_docsis_dcd_cfg_tdsg4;
static int hf_docsis_dcd_cfg_vendor_spec;

static int hf_docsis_mdd_ccc;
static int hf_docsis_mdd_number_of_fragments;
static int hf_docsis_mdd_fragment_sequence_number;
static int hf_docsis_mdd_current_channel_dcid;
static int hf_docsis_mdd_tlv;
static int hf_docsis_mdd_tlv_type;
static int hf_docsis_mdd_tlv_length;
static int hf_docsis_mdd_ds_active_channel_list_subtype;
static int hf_docsis_mdd_ds_active_channel_list_length;
static int hf_docsis_mdd_downstream_active_channel_list_channel_id;
static int hf_docsis_mdd_downstream_active_channel_list_frequency;
static int hf_docsis_mdd_downstream_active_channel_list_annex;
static int hf_docsis_mdd_downstream_active_channel_list_modulation_order;
static int hf_docsis_mdd_downstream_active_channel_list_primary_capable;
static int hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator;
static int hf_docsis_mdd_downstream_active_channel_list_fdx_sub_band_id;
static int hf_docsis_mdd_downstream_active_channel_list_fdx_ds;
static int hf_docsis_mdd_cm_status_event_enable_bitmask;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery;
static int hf_docsis_mdd_ofdm_plc_parameters;
static int hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window;
static int hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix;
static int hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing;
static int hf_docsis_mdd_up_active_channel_list_subtype;
static int hf_docsis_mdd_up_active_channel_list_length;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded;
static int hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded;
static int hf_docsis_mdd_ds_service_group_subtype;
static int hf_docsis_mdd_ds_service_group_length;
static int hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier;
static int hf_docsis_mdd_mac_domain_downstream_service_group_channel_id;
static int hf_docsis_mdd_downstream_ambiguity_resolution_frequency;
static int hf_docsis_mdd_channel_profile_reporting_control_subtype;
static int hf_docsis_mdd_channel_profile_reporting_control_length;
static int hf_docsis_mdd_rcp_center_frequency_spacing;
static int hf_docsis_mdd_verbose_rcp_reporting;
static int hf_docsis_mdd_fragmented_rcp_transmission;
static int hf_docsis_mdd_ip_init_param_subtype;
static int hf_docsis_mdd_ip_init_param_length;
static int hf_docsis_mdd_ip_provisioning_mode;
static int hf_docsis_mdd_pre_registration_dsid;
static int hf_docsis_mdd_early_authentication_and_encryption;
static int hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id;
static int hf_docsis_mdd_upstream_active_channel_list_upstream_channel_priority;
static int hf_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds;
static int hf_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds_dschid;
static int hf_docsis_mdd_upstream_active_channel_list_fdx_upstream_channel;
static int hf_docsis_mdd_upstream_active_channel_list_fdx_subband_id;
static int hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id;
static int hf_docsis_mdd_upstream_frequency_range;
static int hf_docsis_mdd_symbol_clock_locking_indicator;
static int hf_docsis_mdd_cm_status_event_control_subtype;
static int hf_docsis_mdd_cm_status_event_control_length;
static int hf_docsis_mdd_event_type;
static int hf_docsis_mdd_maximum_event_holdoff_timer;
static int hf_docsis_mdd_maximum_number_of_reports_per_event;
static int hf_docsis_mdd_upstream_transmit_power_reporting;
static int hf_docsis_mdd_dsg_da_to_dsid_subtype;
static int hf_docsis_mdd_dsg_da_to_dsid_length;
static int hf_docsis_mdd_dsg_da_to_dsid_association_da;
static int hf_docsis_mdd_dsg_da_to_dsid_association_dsid;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup;
static int hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power;
static int hf_docsis_mdd_extended_upstream_transmit_power_support;

static int hf_docsis_mdd_cmts_major_docsis_version;
static int hf_docsis_mdd_cmts_minor_docsis_version;
static int hf_docsis_mdd_docsis_version_tlv;
static int hf_docsis_mdd_docsis_version_tlv_type;
static int hf_docsis_mdd_docsis_version_tlv_length;
static int hf_docsis_mdd_docsis_version_major_pre_40;
static int hf_docsis_mdd_docsis_version_minor_pre_40;
static int hf_docsis_mdd_docsis_version_major;
static int hf_docsis_mdd_docsis_version_minor;
static int hf_docsis_mdd_docsis_version_ext_spectrum_mode;
static int hf_docsis_mdd_docsis_version_ext_spectrum_mode_fdd;
static int hf_docsis_mdd_docsis_version_ext_spectrum_mode_fdx;

static int hf_docsis_mdd_cm_periodic_maintenance_timeout_indicator;
static int hf_docsis_mdd_dls_broadcast_and_multicast_delivery_method;
static int hf_docsis_mdd_cm_status_event_d31_ofdm_prof_fail;
static int hf_docsis_mdd_cm_status_event_d31_prim_down_chan_change;
static int hf_docsis_mdd_cm_status_event_d31_dpd_mismatch;
static int hf_docsis_mdd_cm_status_event_d31_deprecated;
static int hf_docsis_mdd_cm_status_event_d31_ncp_prof_fail;
static int hf_docsis_mdd_cm_status_event_d31_loss_fec_plc;
static int hf_docsis_mdd_cm_status_event_d31_ncp_prof_recover;
static int hf_docsis_mdd_cm_status_event_d31_fec_recover_on_plc;
static int hf_docsis_mdd_cm_status_event_d31_fec_recover_on_ofdm_prof;
static int hf_docsis_mdd_cm_status_event_d31_ofdma_prof_fail;
static int hf_docsis_mdd_cm_status_event_d31_map_stor_overflow_ind;
static int hf_docsis_mdd_cm_status_event_d31_ofdm_map_stor_almost_full_ind;
static int hf_docsis_mdd_cm_status_event_d31_reserved;

static int hf_docsis_mdd_diplexer_band_edge;
static int hf_docsis_mdd_diplexer_band_edge_length;
static int hf_docsis_mdd_diplexer_us_upper_band_edge;
static int hf_docsis_mdd_diplexer_ds_lower_band_edge;
static int hf_docsis_mdd_diplexer_ds_upper_band_edge;
static int hf_docsis_mdd_diplexer_us_upper_band_edge_override;
static int hf_docsis_mdd_diplexer_ds_lower_band_edge_override;
static int hf_docsis_mdd_diplexer_ds_upper_band_edge_override;

static int hf_docsis_mdd_abp_tlv;
static int hf_docsis_mdd_abp_tlv_type;
static int hf_docsis_mdd_abp_tlv_length;
static int hf_docsis_mdd_abp_sub_band_count;
static int hf_docsis_mdd_abp_sub_band_width;

static int hf_docsis_mdd_bpi_plus_tlv;
static int hf_docsis_mdd_bpi_plus_tlv_type;
static int hf_docsis_mdd_bpi_plus_tlv_length;
static int hf_docsis_mdd_bpi_plus_version;
static int hf_docsis_mdd_bpi_plus_cfg;
static int hf_docsis_mdd_bpi_plus_cfg_eae;

static int hf_docsis_bintrngreq_mddsgid;
static int hf_docsis_bintrngreq_capflags;
static int hf_docsis_bintrngreq_capflags_frag;
static int hf_docsis_bintrngreq_capflags_encrypt;

static int hf_docsis_dbcreq_number_of_fragments;
static int hf_docsis_dbcreq_fragment_sequence_number;

static int hf_docsis_dbcrsp_conf_code;

static int hf_docsis_dpv_flags;
static int hf_docsis_dpv_us_sf;
static int hf_docsis_dpv_n;
static int hf_docsis_dpv_start;
static int hf_docsis_dpv_end;
static int hf_docsis_dpv_ts_start;
static int hf_docsis_dpv_ts_end;

static int hf_docsis_cmstatus_e_t_mdd_t;
static int hf_docsis_cmstatus_e_t_qfl_f;
static int hf_docsis_cmstatus_e_t_s_o;
static int hf_docsis_cmstatus_e_t_mdd_r;
static int hf_docsis_cmstatus_e_t_qfl_r;
static int hf_docsis_cmstatus_e_t_t4_t;
static int hf_docsis_cmstatus_e_t_t3_e;
static int hf_docsis_cmstatus_e_t_rng_s;
static int hf_docsis_cmstatus_e_t_cm_b;
static int hf_docsis_cmstatus_e_t_cm_a;
static int hf_docsis_cmstatus_e_t_mac_removal;
static int hf_docsis_cmstatus_e_t_ds_ofdm_profile_failure;
static int hf_docsis_cmstatus_e_t_prim_ds_change;
static int hf_docsis_cmstatus_e_t_dpd_mismatch;
static int hf_docsis_cmstatus_e_t_ncp_profile_failure;
static int hf_docsis_cmstatus_e_t_plc_failure;
static int hf_docsis_cmstatus_e_t_ncp_profile_recovery;
static int hf_docsis_cmstatus_e_t_plc_recovery;
static int hf_docsis_cmstatus_e_t_ofdm_profile_recovery;
static int hf_docsis_cmstatus_e_t_ofdma_profile_failure;
static int hf_docsis_cmstatus_e_t_map_storage_overflow_indicator;
static int hf_docsis_cmstatus_e_t_map_storage_almost_full_indicator;
static int hf_docsis_cmstatus_e_t_unknown;
static int hf_docsis_cmstatus_status_event_ds_ch_id;
static int hf_docsis_cmstatus_status_event_us_ch_id;
static int hf_docsis_cmstatus_status_event_dsid;
static int hf_docsis_cmstatus_status_event_mac_address;
static int hf_docsis_cmstatus_status_event_ds_ofdm_profile_id;
static int hf_docsis_cmstatus_status_event_us_ofdma_profile_id;
static int hf_docsis_cmstatus_status_event_descr;
static int hf_docsis_cmstatus_tlv_data;
static int hf_docsis_cmstatus_type;
static int hf_docsis_cmstatus_length;
static int hf_docsis_cmstatus_status_event_tlv_data;
static int hf_docsis_cmstatus_status_event_type;
static int hf_docsis_cmstatus_status_event_length;

static int hf_docsis_cmctrl_tlv_mute;
static int hf_docsis_cmctrl_tlv_mute_timeout;
static int hf_docsis_cmctrl_tlv_reinit;
static int hf_docsis_cmctrl_tlv_disable_fwd;
static int hf_docsis_cmctrl_tlv_ds_event;
static int hf_docsis_cmctrl_tlv_us_event;
static int hf_docsis_cmctrl_tlv_event;
static int hf_docsis_cmctrlreq_tlv_data;
static int hf_docsis_cmctrlreq_type;
static int hf_docsis_cmctrlreq_length;
static int hf_docsis_cmctrlreq_us_type;
static int hf_docsis_cmctrlreq_us_length;
static int hf_docsis_cmctrl_us_event_ch_id;
static int hf_docsis_cmctrl_us_event_mask;
static int hf_docsis_cmctrl_ds_type;
static int hf_docsis_cmctrl_ds_length;
static int hf_docsis_cmctrl_ds_event_ch_id;
static int hf_docsis_cmctrl_ds_event_mask;

static int hf_docsis_regreqmp_sid;
static int hf_docsis_regreqmp_number_of_fragments;
static int hf_docsis_regreqmp_fragment_sequence_number;
static int hf_docsis_regrspmp_sid;
static int hf_docsis_regrspmp_response;
static int hf_docsis_regrspmp_number_of_fragments;
static int hf_docsis_regrspmp_fragment_sequence_number;

static int hf_docsis_emrsp_tlv_data;
static int hf_docsis_emrsp_tlv_type;
static int hf_docsis_emrsp_tlv_length;
static int hf_docsis_emrsp_tlv_holdoff_timer;
static int hf_docsis_emreq_req_power_mode;
static int hf_docsis_emreq_reserved;
static int hf_docsis_emrsp_rsp_code;
static int hf_docsis_emrsp_reserved;
static int hf_docsis_emrsp_tlv_unknown;

static int hf_docsis_ocd_tlv_unknown;
static int hf_docsis_ocd_ccc;
static int hf_docsis_ocd_tlv_four_trans_size;
static int hf_docsis_ocd_tlv_cycl_pref;
static int hf_docsis_ocd_tlv_roll_off;
static int hf_docsis_ocd_tlv_ofdm_spec_loc;
static int hf_docsis_ocd_tlv_time_int_depth;
static int hf_docsis_ocd_tlv_prim_cap_ind;
static int hf_docsis_ocd_tlv_fdx_ind;
static int hf_docsis_ocd_tlv_subc_assign_type;
static int hf_docsis_ocd_tlv_subc_assign_value;
static int hf_docsis_ocd_subc_assign_subc_type;
static int hf_docsis_ocd_subc_assign_range;
static int hf_docsis_ocd_subc_assign_index;
static int hf_docsis_ocd_tlv_data;
static int hf_docsis_ocd_type;
static int hf_docsis_ocd_length;

static int hf_docsis_dpd_tlv_unknown;
static int hf_docsis_dpd_prof_id;
static int hf_docsis_dpd_ccc;
static int hf_docsis_dpd_tlv_subc_assign_type;
static int hf_docsis_dpd_tlv_subc_assign_value;
static int hf_docsis_dpd_subc_assign_range;
static int hf_docsis_dpd_tlv_subc_assign_reserved;
static int hf_docsis_dpd_tlv_subc_assign_modulation;
static int hf_docsis_dpd_subc_assign_index;
static int hf_docsis_dpd_tlv_subc_assign_vector_oddness;
static int hf_docsis_dpd_tlv_subc_assign_vector_reserved;
static int hf_docsis_dpd_tlv_subc_assign_vector_subc_start;
static int hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd;
static int hf_docsis_dpd_tlv_subc_assign_vector_modulation_even;
static int hf_docsis_dpd_tlv_data;
static int hf_docsis_dpd_type;
static int hf_docsis_dpd_length;

static int hf_docsis_optreq_tlv_unknown;
static int hf_docsis_optreq_prof_id;
static int hf_docsis_optreq_opcode;
static int hf_docsis_optreq_reserved;
static int hf_docsis_optreq_tlv_data;
static int hf_docsis_optreq_type;
static int hf_docsis_optreq_length;
static int hf_docsis_optreq_reqstat_rxmer_stat_subc;
static int hf_docsis_optreq_reqstat_rxmer_subc_threshold_comp;
static int hf_docsis_optreq_reqstat_snr_marg_cand_prof;
static int hf_docsis_optreq_reqstat_codew_stat_cand_prof;
static int hf_docsis_optreq_reqstat_codew_thresh_comp_cand_prof;
static int hf_docsis_optreq_reqstat_ncp_field_stat;
static int hf_docsis_optreq_reqstat_ncp_crc_thresh_comp;
static int hf_docsis_optreq_reqstat_reserved;
static int hf_docsis_optreq_tlv_rxmer_thresh_data;
static int hf_docsis_optreq_xmer_thresh_params_type;
static int hf_docsis_optreq_xmer_thresh_params_length;
static int hf_docsis_optreq_tlv_rxmer_thresh_data_mod_order;
static int hf_docsis_optreq_tlv_trigger_definition_data;
static int hf_docsis_optreq_tlv_trigger_definition_data_type;
static int hf_docsis_optreq_tlv_trigger_definition_data_length;
static int hf_docsis_optreq_tlv_trigger_definition_trigger_type;
static int hf_docsis_optreq_tlv_trigger_definition_measure_duration;
static int hf_docsis_optreq_tlv_trigger_definition_triggering_sid;
static int hf_docsis_optreq_tlv_trigger_definition_us_chan_id;
static int hf_docsis_optreq_tlv_trigger_definition_sound_ambig_offset;
static int hf_docsis_optreq_tlv_trigger_definition_rx_mer_to_report;
static int hf_docsis_optreq_tlv_trigger_definition_start_time;

static int hf_docsis_optrsp_reserved;
static int hf_docsis_optrsp_prof_id;
static int hf_docsis_optrsp_status;
static int hf_docsis_optrsp_tlv;
static int hf_docsis_optrsp_tlv_type;
static int hf_docsis_optrsp_tlv_length;
static int hf_docsis_optrsp_rxmer_tlv;
static int hf_docsis_optrsp_rxmer_tlv_type;
static int hf_docsis_optrsp_rxmer_tlv_length;
static int hf_docsis_optrsp_rxmer_subcarrier;
static int hf_docsis_optrsp_rxmer_subcarrier_threshold;
static int hf_docsis_optrsp_rxmer_subcarrier_threshold_count;
static int hf_docsis_optrsp_rxmer_snr_margin;
static int hf_docsis_optrsp_rxmer_avg;
static int hf_docsis_optrsp_rxmer_ect_rba_subband_direction;
static int hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb0;
static int hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb1;
static int hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb2;
static int hf_docsis_optrsp_data_cw_tlv;
static int hf_docsis_optrsp_data_cw_tlv_type;
static int hf_docsis_optrsp_data_cw_tlv_length;
static int hf_docsis_optrsp_data_cw_count;
static int hf_docsis_optrsp_data_cw_corrected;
static int hf_docsis_optrsp_data_cw_uncorrectable;
static int hf_docsis_optrsp_data_cw_threshold_comparison;
static int hf_docsis_optrsp_ncp_fields_tlv;
static int hf_docsis_optrsp_ncp_fields_tlv_type;
static int hf_docsis_optrsp_ncp_fields_tlv_length;
static int hf_docsis_optrsp_ncp_fields_count;
static int hf_docsis_optrsp_ncp_fields_failure;
static int hf_docsis_optrsp_ncp_fields_threshold_comparison;

static int hf_docsis_optack_prof_id;
static int hf_docsis_optack_reserved;

static int hf_docsis_rba_tg_id;
static int hf_docsis_rba_ccc;
static int hf_docsis_rba_dcid;
static int hf_docsis_rba_control_byte_bitmask;
static int hf_docsis_rba_resource_block_change_bit;
static int hf_docsis_rba_expiration_time_valid_bit;
static int hf_docsis_rba_control_byte_bitmask_rsvd;
static int hf_docsis_rba_rba_time;
static int hf_docsis_rba_rba_expiration_time;
static int hf_docsis_rba_number_of_subbands;
static int hf_docsis_rba_subband_direction;

/* CWT-REQ and CWT-RSP */
static int hf_docsis_cwt_trans_id;
static int hf_docsis_cwt_sub_band_id;
static int hf_docsis_cwt_op_code;
static int hf_docsis_cwt_status;
static int hf_docsis_cwt_tlv;
static int hf_docsis_cwt_tlv_type;
static int hf_docsis_cwt_tlv_length;
static int hf_docsis_cwt_phase_rotation;
static int hf_docsis_cwt_max_duration;
static int hf_docsis_cwt_us_encodings_tlv;
static int hf_docsis_cwt_us_encodings_tlv_type;
static int hf_docsis_cwt_us_encodings_tlv_length;
static int hf_docsis_cwt_us_encodings_cid;
static int hf_docsis_cwt_us_encodings_sc_index;
static int hf_docsis_cwt_us_encodings_power_boost;

/* ECT-REQ and ECT-RSP */
static int hf_docsis_ect_trans_id;
static int hf_docsis_ect_rsp_code;
static int hf_docsis_ect_tlv;
static int hf_docsis_ect_tlv_type;
static int hf_docsis_ect_tlv_length;
static int hf_docsis_ect_control_tlv;
static int hf_docsis_ect_control_tlv_type;
static int hf_docsis_ect_control_tlv_length;
static int hf_docsis_ect_control_subband_direction;
static int hf_docsis_ect_control_status;
static int hf_docsis_ect_control_method_tlv;
static int hf_docsis_ect_control_method_tlv_type;
static int hf_docsis_ect_control_method_tlv_length;
static int hf_docsis_ect_control_method_fg_tlv;
static int hf_docsis_ect_control_method_fg_tlv_type;
static int hf_docsis_ect_control_method_fg_tlv_length;
static int hf_docsis_ect_control_method_fg_duration;
static int hf_docsis_ect_control_method_fg_periodicity;
static int hf_docsis_ect_control_method_fg_expiration_time;
static int hf_docsis_ect_control_method_fg_ds_zbl;
static int hf_docsis_ect_control_method_bg_tlv;
static int hf_docsis_ect_control_method_bg_tlv_type;
static int hf_docsis_ect_control_method_bg_tlv_length;
static int hf_docsis_ect_control_method_bg_duration;
static int hf_docsis_ect_control_method_bg_periodicity;
static int hf_docsis_ect_control_method_bg_expiration_time;
static int hf_docsis_ect_control_method_bg_start_time;
static int hf_docsis_ect_control_partial_service_tlv;
static int hf_docsis_ect_control_partial_service_tlv_type;
static int hf_docsis_ect_control_partial_service_tlv_length;
static int hf_docsis_ect_control_partial_service_dcid;
static int hf_docsis_ect_control_partial_service_ucid;
static int hf_docsis_ect_control_deferral_time;
static int hf_docsis_ect_control_rxmer_duration;

/* DPR */
static int hf_docsis_dpr_carrier;
static int hf_docsis_dpr_dcid;
static int hf_docsis_dpr_tg_id;
static int hf_docsis_dpr_reserved;
static int hf_docsis_dpr_start_time;
static int hf_docsis_dpr_duration;

static int hf_docsis_mgt_upstream_chid;
static int hf_docsis_mgt_down_chid;
static int hf_docsis_mgt_tranid;
static int hf_docsis_mgt_dst_addr;
static int hf_docsis_mgt_src_addr;
static int hf_docsis_mgt_msg_len;
static int hf_docsis_mgt_dsap;
static int hf_docsis_mgt_ssap;
static int hf_docsis_mgt_30_transmit_power;
static int hf_docsis_mgt_31_transmit_power;
static int hf_docsis_mgt_40_transmit_power;
static int hf_docsis_mgt_control;
static int hf_docsis_mgt_version;
static int hf_docsis_mgt_type;
static int hf_docsis_mgt_rsvd;
static int hf_docsis_mgt_multipart;
static int hf_docsis_mgt_multipart_number_of_fragments;
static int hf_docsis_mgt_multipart_fragment_sequence_number;

static int hf_docsis_tlv_fragments;
static int hf_docsis_tlv_fragment;
static int hf_docsis_tlv_fragment_overlap;
static int hf_docsis_tlv_fragment_overlap_conflict;
static int hf_docsis_tlv_fragment_multiple_tails;
static int hf_docsis_tlv_fragment_too_long_fragment;
static int hf_docsis_tlv_fragment_error;
static int hf_docsis_tlv_fragment_count;
static int hf_docsis_tlv_reassembled_in;
static int hf_docsis_tlv_reassembled_length;
static int hf_docsis_tlv_reassembled_data;

static int hf_docsis_tlv_reassembled;

static int ett_docsis_sync;

static int ett_docsis_ucd;
static int ett_docsis_tlv;
static int ett_docsis_burst_tlv;

static int ett_docsis_map;
static int ett_docsis_map_ie;
static int ett_docsis_map_probe_ie;


static int ett_docsis_rngreq;

static int ett_docsis_rngrsp;
static int ett_docsis_rngrsptlv;
static int ett_docsis_rngrsp_tlv_transmit_equalization_encodings;
static int ett_docsis_rngrsp_tlv_transmit_equalization_encodings_coef;
static int ett_docsis_rngrsp_tlv_commanded_power_subtlv;
static int ett_docsis_rngrsp_tlv_commanded_power;


static int ett_docsis_regreq;
static int ett_docsis_regrsp;

static int ett_docsis_emreq;
static int ett_docsis_emrsp;
static int ett_docsis_emrsp_tlv;
static int ett_docsis_emrsp_tlvtlv;

static int ett_docsis_uccreq;
static int ett_docsis_uccrsp;

static int ett_docsis_bpkmreq;
static int ett_docsis_bpkmrsp;
static int ett_docsis_bpkmattr;
static int ett_docsis_bpkmattr_tlv;
static int ett_docsis_bpkmattr_cmid;
static int ett_docsis_bpkmattr_scap;
static int ett_docsis_bpkmattr_crypto_suite;
static int ett_docsis_bpkmattr_crypto_suite_list;
static int ett_docsis_bpkmattr_allowed_bpi_versions;
static int ett_docsis_bpkmattr_ocsp_responses;
static int ett_docsis_bpkmattr_cmts_designation;
static int ett_docsis_bpkmattr_tekp;
static int ett_docsis_bpkmattr_sadsc;
static int ett_docsis_bpkmattr_saqry;
static int ett_docsis_bpkmattr_dnld;

static int ett_docsis_regack;

static int ett_docsis_dsareq;
static int ett_docsis_dsarsp;
static int ett_docsis_dsaack;

static int ett_docsis_dscreq;
static int ett_docsis_dscrsp;
static int ett_docsis_dscack;

static int ett_docsis_dsdreq;
static int ett_docsis_dsdrsp;

static int ett_docsis_dccreq;
static int ett_docsis_dccreq_tlv;
static int ett_docsis_dccreq_ds_params;
static int ett_docsis_dccreq_sf_sub;
static int ett_docsis_dccrsp;
static int ett_docsis_dccrsp_cm_jump_time;
static int ett_docsis_dccrsp_tlv;
static int ett_docsis_dccack;
static int ett_docsis_dccack_tlv;

static int ett_docsis_intrngreq;

static int ett_docsis_dcd;
static int ett_docsis_dcd_cfr;
static int ett_docsis_dcd_cfr_ip;
static int ett_docsis_dcd_rule;
static int ett_docsis_dcd_clid;
static int ett_docsis_dcd_cfg;
static int ett_docsis_dcd_tlv;

static int ett_docsis_mdd;
static int ett_tlv;
static int ett_sub_tlv;
static int ett_docsis_mdd_cm_status_ev_en_for_docsis31;
static int ett_docsis_mdd_ds_active_channel_list;
static int ett_docsis_mdd_ds_service_group;
static int ett_docsis_mdd_channel_profile_reporting_control;
static int ett_docsis_mdd_ip_init_param;
static int ett_docsis_mdd_up_active_channel_list;
static int ett_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds_dschids;
static int ett_docsis_mdd_cm_status_event_control;
static int ett_docsis_mdd_dsg_da_to_dsid;
static int ett_docsis_mdd_docsis_version;
static int ett_docsis_mdd_docsis_version_tlv;
static int ett_docsis_mdd_diplexer_band_edge;
static int ett_docsis_mdd_advanced_band_plan;
static int ett_docsis_mdd_bpi_plus;

static int ett_docsis_bintrngreq;

static int ett_docsis_dbcreq;
static int ett_docsis_dbcrsp;
static int ett_docsis_dbcack;

static int ett_docsis_dpvreq;
static int ett_docsis_dpvrsp;

static int ett_docsis_cmstatus;
static int ett_docsis_cmstatus_tlv;
static int ett_docsis_cmstatus_tlvtlv;
static int ett_docsis_cmstatus_status_event_tlv;
static int ett_docsis_cmstatus_status_event_tlvtlv;

static int ett_docsis_cmstatusack;

static int ett_docsis_cmctrlreq;
static int ett_docsis_cmctrlreq_tlv;
static int ett_docsis_cmctrlreq_tlvtlv;
static int ett_docsis_cmctrl_tlv_us_event;
static int ett_docsis_cmctrl_tlv_ds_event;
static int ett_docsis_cmctrlrsp;

static int ett_docsis_regreqmp;
static int ett_docsis_regrspmp;

static int ett_docsis_ocd;
static int ett_docsis_ocd_tlv;
static int ett_docsis_ocd_tlvtlv;

static int ett_docsis_dpd;
static int ett_docsis_dpd_tlv;
static int ett_docsis_dpd_tlvtlv;
static int ett_docsis_dpd_tlv_subcarrier_assignment;
static int ett_docsis_dpd_tlv_subcarrier_assignment_vector;

static int ett_docsis_optreq;
static int ett_docsis_optreq_tlv;
static int ett_docsis_optreq_tlvtlv;
static int ett_docsis_optreq_tlv_rxmer_thresh_params;
static int ett_docsis_optreq_tlv_rxmer_thresh_params_tlv;
static int ett_docsis_optreq_tlv_trigger_definition_params;
static int ett_docsis_optreq_tlv_trigger_definition_params_tlv;

static int ett_docsis_optrsp;
static int ett_docsis_optrsp_tlv;
static int ett_docsis_optrsp_rxmer_tlv;
static int ett_docsis_optrsp_rxmer_subcarrier_tlv;
static int ett_docsis_optrsp_data_cw_tlv;
static int ett_docsis_optrsp_ncp_fields_tlv;

static int ett_docsis_optack;

static int ett_docsis_rba;
static int ett_docsis_rba_control_byte;
static int ett_docsis_cwt_req;
static int ett_docsis_cwt_rsp;
static int ett_docsis_cwt_tlv;
static int ett_docsis_cwt_subtlv;
static int ett_docsis_ect_req;
static int ett_docsis_ect_rsp;
static int ett_docsis_ect_tlv;
static int ett_docsis_ext_rngreq;
static int ett_docsis_dpr;

static int ett_docsis_mgmt;
static int ett_mgmt_pay;

static int ett_docsis_tlv_fragments;
static int ett_docsis_tlv_fragment;
static int ett_docsis_tlv_reassembled;

static expert_field ei_docsis_mgmt_tlvlen_bad;
static expert_field ei_docsis_mgmt_tlvtype_unknown;
static expert_field ei_docsis_mgmt_version_unknown;
static expert_field ei_docsis_mgmt_opt_req_trigger_def_measure_duration;
static expert_field ei_docsis_cwt_out_of_range;
static expert_field ei_docsis_ect_control_out_of_range;
static expert_field ei_docsis_dpr_out_of_range;

static dissector_table_t docsis_mgmt_dissector_table;
static dissector_handle_t docsis_tlv_handle;
static dissector_handle_t docsis_ucd_handle;
static dissector_handle_t docsis_rba_handle;

static const value_string channel_tlv_vals[] = {
  {UCD_SYMBOL_RATE,  "Symbol Rate"},
  {UCD_FREQUENCY,    "Frequency"},
  {UCD_PREAMBLE,     "Preamble Pattern"},
  {UCD_BURST_DESCR,  "Burst Descriptor Type 4"},
  {UCD_BURST_DESCR5, "Burst Descriptor Type 5"},
  {UCD_EXT_PREAMBLE, "Extended Preamble Pattern"},
  {UCD_SCDMA_MODE_ENABLED, "S-CDMA Mode Enabled"},
  {UCD_SCDMA_SPREADING_INTERVAL, "S-CDMA Spreading Intervals per Frame"},
  {UCD_SCDMA_CODES_PER_MINI_SLOT, "S-CDMA Codes per Mini-slot"},
  {UCD_SCDMA_ACTIVE_CODES, "S-CDMA Number of Active Codes"},
  {UCD_SCDMA_CODE_HOPPING_SEED, "S-CDMA Code Hopping Seed"},
  {UCD_SCDMA_US_RATIO_NUM, "S-CDMA US ratio numerator M"},
  {UCD_SCDMA_US_RATIO_DENOM, "S-CDMA US ratio denominator N"},
  {UCD_SCDMA_TIMESTAMP_SNAPSHOT, "S-CDMA Timestamp Snapshot"},
  {UCD_MAINTAIN_POWER_SPECTRAL_DENSITY, "Maintain Power Spectral Density"},
  {UCD_RANGING_REQUIRED, "Ranging Required"},
  {UCD_MAX_SCHEDULED_CODES, "S-CDMA Maximum Scheduled Codes"},
  {UCD_RANGING_HOLD_OFF_PRIORITY_FIELD, "Ranging Hold-Off Priority Field"},
  {UCD_RANGING_CHANNEL_CLASS_ID, "Ranging Channel Class ID"},
  {UCD_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING, "S-CDMA Selection Mode for Active Codes and Code Hopping"},
  {UCD_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES, "S-CDMA Selection String for Active Codes"},
  {UCD_HIGHER_UCD_FOR_SAME_UCID,        "Higher UCD for the same UCID present bitmap"},
  {UCD_BURST_DESCR23,                   "Burst Descriptor Type 23"},
  {UCD_CHANGE_IND_BITMASK,              "UCD Change Indicator Bitmask"},
  {UCD_OFDMA_TIMESTAMP_SNAPSHOT,        "OFDMA Timestamp Snapshot"},
  {UCD_OFDMA_CYCLIC_PREFIX_SIZE,        "OFDMA Cyclic Prefix Size"},
  {UCD_OFDMA_ROLLOFF_PERIOD_SIZE,       "OFDMA Rolloff Period Size"},
  {UCD_SUBCARRIER_SPACING,              "Subcarrier Spacing"},
  {UCD_CENTER_FREQ_SUBC_0,              "Center Frequency of Subcarrier 0"},
  {UCD_SUBC_EXCL_BAND,                  "Subcarrier Exclusion Band"},
  {UCD_UNUSED_SUBC_SPEC,                "Unused Subcarrier Specification"},
  {UCD_SYMB_IN_OFDMA_FRAME,             "Symbols in OFDMA frame"},
  {UCD_RAND_SEED,                       "Randomization Seed"},
  {EXTENDED_US_CHANNEL,                 "Extended Upstream Channel"},
  {0, NULL}
};

static const value_string burst_tlv_vals[] = {
  {UCD_MODULATION,                      "Modulation Type"},
  {UCD_DIFF_ENCODING,                   "Differential Encoding"},
  {UCD_PREAMBLE_LEN,                    "Preamble Length"},
  {UCD_PREAMBLE_VAL_OFF,                "Preamble Value Offset"},
  {UCD_FEC,                             "FEC Error Correction (T)"},
  {UCD_FEC_CODEWORD,                    "FEC Codeword Information Bytes (k)"},
  {UCD_SCRAMBLER_SEED,                  "Scrambler Seed"},
  {UCD_MAX_BURST,                       "Maximum Burst Size"},
  {UCD_GUARD_TIME,                      "Guard Time Size"},
  {UCD_LAST_CW_LEN,                     "Last Codeword Length"},
  {UCD_SCRAMBLER_ONOFF,                 "Scrambler on/off"},
  {UCD_RS_INT_DEPTH,                    "R-S Interleaver Depth (Ir)"},
  {UCD_RS_INT_BLOCK,                    "R-S Interleaver Block Size (Br)"},
  {UCD_PREAMBLE_TYPE,                   "Preamble Type"},
  {UCD_SCMDA_SCRAMBLER_ONOFF,           "S-CDMA Spreader on/off"},
  {UCD_SCDMA_CODES_PER_SUBFRAME,        "S-CDMA Codes per Subframe"},
  {UCD_SCDMA_FRAMER_INT_STEP_SIZE,      "S-CDMA Framer Interleaving Step Size"},
  {UCD_TCM_ENABLED,                     "TCM Encoding"},
  {UCD_SUBC_INIT_RANG,                  "Subcarriers (Nir) Initial Ranging"},
  {UCD_SUBC_FINE_RANG,                  "Subcarriers (Nfr) Fine Ranging"},
  {UCD_OFDMA_PROFILE,                   "OFDMA Profile"},
  {UCD_OFDMA_IR_POWER_CONTROL,          "OFDMA Power Control (Ir)"},
  {0, NULL}
};

static const value_string mgmt_type_vals[] = {
  {MGT_SYNC,           "Timing Synchronisation"},
  {MGT_UCD,            "Upstream Channel Descriptor"},
  {MGT_TYPE29UCD,      "Upstream Channel Descriptor Type 29"},
  {MGT_TYPE35UCD,      "Upstream Channel Descriptor Type 35"},
  {MGT_MAP,            "Upstream Bandwidth Allocation"},
  {MGT_RNG_REQ,        "Ranging Request"},
  {MGT_RNG_RSP,        "Ranging Response"},
  {MGT_REG_REQ,        "Registration Request"},
  {MGT_REG_RSP,        "Registration Response"},
  {MGT_UCC_REQ,        "Upstream Channel Change Request"},
  {MGT_UCC_RSP,        "Upstream Channel Change Response"},
  {MGT_TRI_TCD,        "Telephony Channel Descriptor"},
  {MGT_TRI_TSI,        "Termination System Information"},
  {MGT_BPKM_REQ,       "Privacy Key Management Request"},
  {MGT_BPKM_RSP,       "Privacy Key Management Response"},
  {MGT_REG_ACK,        "Registration Acknowledge"},
  {MGT_DSA_REQ,        "Dynamic Service Addition Request"},
  {MGT_DSA_RSP,        "Dynamic Service Addition Response"},
  {MGT_DSA_ACK,        "Dynamic Service Addition  Acknowledge"},
  {MGT_DSC_REQ,        "Dynamic Service Change Request"},
  {MGT_DSC_RSP,        "Dynamic Service Change Response"},
  {MGT_DSC_ACK,        "Dynamic Service Change Acknowledge"},
  {MGT_DSD_REQ,        "Dynamic Service Delete Request"},
  {MGT_DSD_RSP,        "Dynamic Service Delete Response"},
  {MGT_DCC_REQ,        "Dynamic Channel Change Request"},
  {MGT_DCC_RSP,        "Dynamic Channel Change Response"},
  {MGT_DCC_ACK,        "Dynamic Channel Change Acknowledge"},
  {MGT_DCI_REQ,        "Device Class Identification Request"},
  {MGT_DCI_RSP,        "Device Class Identification Response"},
  {MGT_UP_DIS,         "Upstream Channel Disable"},
  {MGT_INIT_RNG_REQ,   "Initial Ranging Request"},
  {MGT_TEST_REQ,       "Test Request Message"},
  {MGT_DS_CH_DESC,     "Downstream Channel Descriptor"},
  {MGT_MDD,            "MAC Domain Descriptor"},
  {MGT_B_INIT_RNG_REQ, "Bonded Initial Ranging Request"},
  {MGT_DBC_REQ,        "Dynamic Bonding Change Request"},
  {MGT_DBC_RSP,        "Dynamic Bonding Change Response"},
  {MGT_DBC_ACK,        "Dynamic Bonding Change Acknowledge"},
  {MGT_DPV_REQ,        "DOCSIS Path Verify Request"},
  {MGT_DPV_RSP,        "DOCSIS Path Verify Response"},
  {MGT_CM_STATUS,      "CM Status Report"},
  {MGT_CM_CTRL_REQ,    "CM Control Request"},
  {MGT_CM_CTRL_RSP,    "CM Control Response"},
  {MGT_REG_REQ_MP,     "Multipart Registration Request"},
  {MGT_REG_RSP_MP,     "Multipart Registration Response"},
  {MGT_EM_REQ,         "Energy Management Request"},
  {MGT_EM_RSP,         "Energy Management Response"},
  {MGT_CM_STATUS_ACK,     "Status Report Acknowledge"},
  {MGT_OCD,            "OFDM Channel Descriptor"},
  {MGT_DPD,            "Downstream Profile Descriptor"},
  {MGT_TYPE51UCD,      "Upstream Channel Descriptor Type 51"},
  {MGT_ODS_REQ,        "ODS-REQ"},
  {MGT_ODS_RSP,        "ODS-RSP"},
  {MGT_OPT_REQ,        "OFDM Downstream Profile Test Request"},
  {MGT_OPT_RSP,        "OFDM Downstream Profile Test Response"},
  {MGT_OPT_ACK,        "OFDM Downstream Profile Test Acknowledge"},
  {MGT_DPT_REQ,        "DOCSIS Time Protocol Request"},
  {MGT_DPT_RSP,        "DOCSIS Time Protocol Response"},
  {MGT_DPT_ACK,        "DOCSIS Time Protocol Acknowledge"},
  {MGT_DPT_INFO,       "DOCSIS Time Protocol Information"},
  {MGT_RBA_SW,         "DOCSIS SW-Friendly Resource Block Assignment"},
  {MGT_RBA_HW,         "DOCSIS HW-Friendly Resource Block Assignment"},
  {MGT_CWT_REQ,        "IG Discovery CW Test Request"},
  {MGT_CWT_RSP,        "IG Discovery CW Test Response"},
  {MGT_ECT_REQ,        "CM Echo Cancellation Training Request"},
  {MGT_ECT_RSP,        "CM Echo Cancellation Training Response"},
  {MGT_EXT_RNG_REQ,    "Extended Upstream Range Request"},
  {MGT_DPR,            "Downstream Protection"},
  {MGT_BPKM_REQ_V5,    "Privacy Key Management Request v5"},
  {MGT_BPKM_RSP_V5,    "Privacy Key Management Response v5"},
  {0, NULL}
};

static const value_string on_off_vals[] = {
  {1, "On"},
  {2, "Off"},
  {0, NULL}
};

static const value_string inhibit_allow_vals[] = {
  {0, "Inhibit Initial Ranging"},
  {1, "Ranging Allowed"},
  {0, NULL},
};

static const value_string mod_vals[] = {
  {1, "QPSK"},
  {2, "16-QAM"},
  {3, "8-QAM"},
  {4, "32-QAM"},
  {5, "64-QAM"},
  {6, "128-QAM (SCDMA-only)"},
  {7, "Reserved for C-DOCSIS"},
  {0, NULL}
};

static const value_string iuc_vals[] = {
  {IUC_REQUEST,                  "Request"},
  {IUC_REQ_DATA,                 "REQ/Data"},
  {IUC_INIT_MAINT,               "Initial Maintenance"},
  {IUC_STATION_MAINT,            "Station Maintenance"},
  {IUC_SHORT_DATA_GRANT,         "Short Data Grant"},
  {IUC_LONG_DATA_GRANT,          "Long Data Grant"},
  {IUC_NULL_IE,                  "NULL IE"},
  {IUC_DATA_ACK,                 "Data Ack"},
  {IUC_ADV_PHY_SHORT_DATA_GRANT, "Advanced Phy Short Data Grant"},
  {IUC_ADV_PHY_LONG_DATA_GRANT,  "Advanced Phy Long Data Grant"},
  {IUC_ADV_PHY_UGS,              "Advanced Phy UGS"},
  {IUC_DATA_PROFILE_IUC12,       "Data Profile IUC12"},
  {IUC_DATA_PROFILE_IUC13,       "Data Profile IUC13"},
  {IUC_RESERVED14,               "Reserved"},
  {IUC_EXPANSION,                "Expanded IUC"},
  {0, NULL}
};

static const true_false_string pw_vals = {"transmit using alternate power setting specified by the Start Subc field.", "transmit using normal power settings"};

static const value_string map_ect_vals[] = {
  {0, "Ranging probe"},
  {1, "ECT probe"},
  {2, "ECT RxMER probe"},
  {3, "First ECT probe"},
  {4, "First ECT RxMER probe"},
  {0, NULL}
};

static const value_string last_cw_len_vals[] = {
  {1, "Fixed"},
  {2, "Shortened"},
  {0, NULL}
};

static const value_string ranging_req_vals[] = {
  {0, "No ranging required"},
  {1, "Unicast initial ranging required"},
  {2, "Broadcast initial ranging required"},
  {0, NULL}
};

static const value_string rng_stat_vals[] = {
  {1, "Continue"},
  {2, "Abort"},
  {3, "Success"},
  {0, NULL}
};

static void
two_compl_frac(
    char *buf,
    int16_t value)
{
    int16_t frac = value;


    snprintf(buf, ITEM_LABEL_LENGTH,
        "%f",
        frac/16384.0);
}

static const value_string rngrsp_tlv_vals[] = {
  {RNGRSP_TIMING,            "Timing Adjust (6.25us/64)"},
  {RNGRSP_PWR_LEVEL_ADJ,     "Power Level Adjust (0.25dB units)"},
  {RNGRSP_OFFSET_FREQ_ADJ,   "Offset Freq Adjust (Hz)"},
  {RNGRSP_TRANSMIT_EQ_ADJ,   "Transmit Equalization Adjust"},
  {RNGRSP_RANGING_STATUS,    "Ranging Status"},
  {RNGRSP_DOWN_FREQ_OVER,    "Downstream Frequency Override (Hz)"},
  {RNGRSP_UP_CHID_OVER,      "Upstream Channel ID Override"},
  {RNGRSP_TRANSMIT_EQ_SET,   "Transmit Equalization Set"},
  {RNGRSP_T4_TIMEOUT_MULTIPLIER, "T4 Timeout Multiplier"},
  {RNGRSP_DYNAMIC_RANGE_WINDOW_UPPER_EDGE, "Dynamic Range Window Upper Edge"},
  {RNGRSP_TRANSMIT_EQ_ADJUST_OFDMA_CHANNELS, "Transmit Equalization Adjust for OFDMA Channels"},
  {RNGRSP_TRANSMIT_EQ_SET_OFDMA_CHANNELS, "Transmit Equalization Set for OFDMA Channels"},
  {RNGRSP_COMMANDED_POWER, "Commanded Power"},
  {RNGRSP_EXT_US_COMMANDED_POWER, "Extended Upstream Commanded Power"},
  {0, NULL}
};


static const value_string rngrsp_tlv_commanded_power_subtlv_vals[] = {
  {RNGRSP_COMMANDED_POWER_DYNAMIC_RANGE_WINDOW, "Dynamic Range Window"},
  {RNGRSP_COMMANDED_POWER_UCID_AND_POWER_LEVEL_LIST, "List of Upstream Channel IDs and Corresponding Transmit Power Levels"},
  {0, NULL}
};

static const value_string code_field_vals[] = {
  { 4, "Auth Request"},
  { 5, "Auth Reply"},
  { 6, "Auth Reject"},
  { 7, "Key Request"},
  { 8, "Key Reply"},
  { 9, "Key Reject"},
  {10, "Auth Invalid"},
  {11, "TEK Invalid"},
  {12, "Auth Info"},
  {13, "Map Request"},
  {14, "Map Reply"},
  {15, "Map Reject"},
  {16, "Auth Status Info"},
  {0, NULL},
};

static const value_string ds_mod_type_vals[] = {
  {0 , "64 QAM"},
  {1 , "256 QAM"},
  {0, NULL}
};

static const value_string ds_sym_rate_vals[] = {
  {0 , "5.056941 Msym/sec"},
  {1 , "5.360537 Msym/sec"},
  {2 , "6.952 Msym/sec"},
  {0, NULL}
};
static const value_string init_tech_vals[] = {
  {0 , "Reinitialize MAC"},
  {1 , "Broadcast Init RNG on new chanbefore normal op"},
  {2 , "Unicast RNG on new chan before normal op"},
  {3 , "Either Unicast or broadcast RNG on new chan before normal op"},
  {4 , "Use new chan directly without re-init or RNG"},
  {0, NULL}
};

static const value_string dcc_tlv_vals[] = {
  {DCCREQ_UP_CHAN_ID, "Up Channel ID"},
  {DCCREQ_DS_PARAMS, "Downstream Params Encodings"},
  {DCCREQ_INIT_TECH, "Initialization Technique"},
  {DCCREQ_UCD_SUB, "UCD Substitution"},
  {DCCREQ_SAID_SUB, "SAID Sub"},
  {DCCREQ_SF_SUB, "Service Flow Substitution Encodings"},
  {DCCREQ_CMTS_MAC_ADDR, "CMTS MAC Address"},
  {DCCREQ_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {DCCREQ_HMAC_DIGEST, "HMAC-DigestNumber"},
  {0, NULL}
};

static const value_string ds_param_subtlv_vals[] = {
  {DCCREQ_DS_FREQ, "Frequency"},
  {DCCREQ_DS_MOD_TYPE, "Modulation Type"},
  {DCCREQ_DS_SYM_RATE, "Symbol Rate"},
  {DCCREQ_DS_INTLV_DEPTH, "Interleaver Depth"},
  {DCCREQ_DS_CHAN_ID, "Downstream Channel ID"},
  {DCCREQ_DS_SYNC_SUB, "SYNC Substitution"},
  {DCCREQ_DS_OFDM_BLOCK_FREQ, "OFDM Block Frequency"},
  {0, NULL}
};

static const value_string sf_sub_subtlv_vals[] = {
  {DCCREQ_SF_SFID, "SFID"},
  {DCCREQ_SF_SID, "SID"},
  {DCCREQ_SF_UNSOL_GRANT_TREF, "Unsolicited Grant Time Reference"},
  {0, NULL}
};

static const value_string dccrsp_tlv_vals[] = {
  {DCCRSP_CM_JUMP_TIME, "CM Jump Time Encodings"},
  {DCCRSP_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {DCCRSP_HMAC_DIGEST, "HMAC-Digest Number"},
  {0, NULL}
};

static const value_string cm_jump_subtlv_vals[] = {
  {DCCRSP_CM_JUMP_TIME_LENGTH, "Length of Jump"},
  {DCCRSP_CM_JUMP_TIME_START, "Start Time of Jump"},
  {0, NULL}
};

static const value_string dccack_tlv_vals[] = {
  {DCCACK_HMAC_DIGEST, "HMAC-DigestNumber"},
  {DCCACK_KEY_SEQ_NUM, "Auth Key Sequence Number"},
  {0, NULL}
};

static const value_string max_scheduled_codes_vals[] = {
  {1, "Enabled"},
  {2, "Disabled"},
  {0, NULL}
};

static const value_string dcd_tlv_vals[] = {
  {DCD_DOWN_CLASSIFIER, "DCD_CFR Encodings"},
  {DCD_DSG_RULE, "DCD DSG Rule Encodings"},
  {DCD_DSG_CONFIG, "DCD DSG Config Encodings"},
  {0, NULL}
};

static const value_string dcd_down_classifier_vals[] = {
  {DCD_CFR_ID, "Downstream Classifier ID"},
  {DCD_CFR_RULE_PRI, "Downstream Classifier Rule Priority"},
  {DCD_CFR_IP_CLASSIFIER, "DCD_CFR_IP Encodings"},
  {0, NULL}
};

static const value_string dcd_dsg_rule_vals[] = {
  {DCD_RULE_ID, "DSG Rule ID"},
  {DCD_RULE_PRI, "DSG Rule Priority"},
  {DCD_RULE_UCID_RNG, "DSG Rule UCID Range"},
  {DCD_RULE_CLIENT_ID, "DCD Rule ClientID Encodings"},
  {DCD_RULE_TUNL_ADDR, "DSG Rule Tunnel MAC Address"},
  {DCD_RULE_CFR_ID, "DSG Rule Classifier ID"},
  {DCD_RULE_VENDOR_SPEC, "DSG Rule Vendor Specific Parameters"},
  {0, NULL}
};

static const value_string dcd_clid_vals[] = {
  {DCD_CLID_BCAST_ID, "DSG Rule Client ID Broadcast ID"},
  {DCD_CLID_KNOWN_MAC_ADDR, "DSG Rule Client ID Known MAC Address"},
  {DCD_CLID_CA_SYS_ID, "DSG Rule Client ID CA System ID"},
  {DCD_CLID_APP_ID, "DSG Rule Client ID Application ID"},
  {0, NULL}
};

static const value_string dcd_cfr_ip_vals[] = {
  {DCD_CFR_IP_SOURCE_ADDR, "Downstream Classifier IP Source Address"},
  {DCD_CFR_IP_SOURCE_MASK, "Downstream Classifier IP Source Mask"},
  {DCD_CFR_IP_DEST_ADDR, "Downstream Classifier IP Destination Address"},
  {DCD_CFR_IP_DEST_MASK, "Downstream Classifier IP Destination Mask"},
  {DCD_CFR_TCPUDP_SRCPORT_START, "Downstream Classifier IP TCP/UDP Source Port Start"},
  {DCD_CFR_TCPUDP_SRCPORT_END, "Downstream Classifier IP TCP/UDP Source Port End"},
  {DCD_CFR_TCPUDP_DSTPORT_START, "Downstream Classifier IP TCP/UDP Destination Port Start"},
  {DCD_CFR_TCPUDP_DSTPORT_END, "Downstream Classifier IP TCP/UDP Destination Port End"},
  {0, NULL}
};

static const value_string dcd_cfg_vals[] = {
  {DCD_CFG_CHAN_LST, "DSG Configuration Channel"},
  {DCD_CFG_TDSG1, "DSG Initialization Timeout (Tdsg1)"},
  {DCD_CFG_TDSG2, "DSG Initialization Timeout (Tdsg2)"},
  {DCD_CFG_TDSG3, "DSG Initialization Timeout (Tdsg3)"},
  {DCD_CFG_TDSG4, "DSG Initialization Timeout (Tdsg4)"},
  {DCD_CFG_VENDOR_SPEC, "DSG Configuration Vendor Specific Parameters"},
  {0, NULL}
};

static const value_string J83_annex_vals[] = {
  {J83_ANNEX_A, "J.83 Annex A"},
  {J83_ANNEX_B, "J.83 Annex B"},
  {J83_ANNEX_C, "J.83 Annex C"},
  {0, NULL}
};

static const value_string modulation_order_vals[] = {
  {QAM64,  "64-QAM"},
  {QAM256, "256-QAM"},
  {0, NULL}
};

static const value_string primary_capable_vals[] = {
  {NOT_PRIMARY_CAPABLE, "Channel is not primary-capable"},
  {PRIMARY_CAPABLE, "Channel is primary-capable"},
  {2, "Reserved (was FDX downstream channel)"},
  {0, NULL}
};

static const value_string map_ucd_transport_indicator_vals[] = {
  {CANNOT_CARRY_MAP_UCD, "Channel cannot carry MAPs and UCDs for the MAC domain for which the MDD is sent"},
  {CAN_CARRY_MAP_UCD,    "Channel can carry MAPs and UCDs for the MAC domain for which the MDD is sent"},
  {0, NULL}
};

static const value_string mdd_downstream_active_channel_list_fdx_vals[] = {
  {0, "Not an FDX Downstream Channel"},
  {1, "FDX Downstream Channel"},
  {0, NULL}
};

static const value_string tukey_raised_cosine_vals[] = {
  {TUKEY_0TS,   "0 "UTF8_MICRO_SIGN"s (0 * Ts)"},
  {TUKEY_64TS,  "0.3125 "UTF8_MICRO_SIGN"s (64 * Ts)"},
  {TUKEY_128TS, "0.625 "UTF8_MICRO_SIGN"s (128 * Ts)"},
  {TUKEY_192TS, "0.9375 "UTF8_MICRO_SIGN"s (192 * Ts)"},
  {TUKEY_256TS, "1.25 "UTF8_MICRO_SIGN"s (256 * Ts)"},
  {0, NULL}
};

static const value_string cyclic_prefix_vals[] = {
  {CYCLIC_PREFIX_192_TS,  "0.9375 "UTF8_MICRO_SIGN"s (192 * Ts)"},
  {CYCLIC_PREFIX_256_TS,  "1.25 "UTF8_MICRO_SIGN"s (256 * Ts)"},
  {CYCLIC_PREFIX_512_TS,  "2.5 "UTF8_MICRO_SIGN"s (512 * Ts) 3"},
  {CYCLIC_PREFIX_768_TS,  "3.75 "UTF8_MICRO_SIGN"s (768 * Ts)"},
  {CYCLIC_PREFIX_1024_TS, "5 "UTF8_MICRO_SIGN"s (1024 * Ts)"},
  {0, NULL}
};

static const value_string spacing_vals[] = {
  {SPACING_25KHZ, "25kHz"},
  {SPACING_50KHZ, "50kHz"},
  {0, NULL}
};

static const value_string bpkmattr_tlv_vals[] = {
  {BPKM_RESERVED,           "Reserved"},
  {BPKM_SERIAL_NUM,         "Serial Number"},
  {BPKM_MANUFACTURER_ID,    "Manufacturer ID"},
  {BPKM_MAC_ADDR,           "MAC Address"},
  {BPKM_RSA_PUB_KEY,        "RSA Public Key"},
  {BPKM_CM_ID,              "CM Identification"},
  {BPKM_DISPLAY_STR,        "Display String"},
  {BPKM_AUTH_KEY,           "Auth Key (encrypted)"},
  {BPKM_TEK,                "Traffic Encryption Key"},
  {BPKM_KEY_LIFETIME,       "Key Lifetime"},
  {BPKM_KEY_SEQ_NUM,        "Key Sequence Number"},
  {BPKM_HMAC_DIGEST,        "HMAC Digest"},
  {BPKM_SAID,               "SAID"},
  {BPKM_TEK_PARAM,          "TEK Parameters"},
  {BPKM_OBSOLETED,          "Obsoleted"},
  {BPKM_CBC_IV,             "CBC IV"},
  {BPKM_ERROR_CODE,         "Error Code"},
  {BPKM_CA_CERT,            "CA Certificate"},
  {BPKM_CM_CERT,            "CM Certificate"},
  {BPKM_SEC_CAPABILITIES,   "Security Capabilities"},
  {BPKM_CRYPTO_SUITE,       "Cryptographic Suite"},
  {BPKM_CRYPTO_SUITE_LIST,  "Cryptographic Suite List"},
  {BPKM_BPI_VERSION,        "BPI Version"},
  {BPKM_SA_DESCRIPTOR,      "SA Descriptor"},
  {BPKM_SA_TYPE,            "SA Type"},
  {BPKM_SA_QUERY,           "SA Query"},
  {BPKM_SA_QUERY_TYPE,      "SA Query Type"},
  {BPKM_IP_ADDRESS,         "IP Address"},
  {BPKM_DNLD_PARAMS,        "Download Parameters"},
  {BPKM_CVC_ROOT_CA_CERT,   "CVC Root CA Certificate"},
  {BPKM_CVC_CA_CERT,        "CVC CA Certificate"},
  {BPKM_DEV_CA_CERT,        "Device CA Certificate"},
  {BPKM_ROOT_CA_CERT,       "Root CA Certificate"},
  {BPKM_CM_NONCE,           "CM Nonce"},
  {BPKM_MSG_SIGNATURE,      "Message Signature"},
  {BPKM_KEY_EXCHANGE_SHARE, "Key Exchange Share"},
  {BPKM_ALLOWED_BPI_VERSIONS, "Allowed BPI Versions"},
  {BPKM_OCSP_RSP,           "OCSP Responses"},
  {BPKM_CMTS_DESIGNATION,   "CMTS Designation"},
  {BPKM_CM_STATUS_CODE,     "CM-Status Code"},
  {BPKM_DETECTED_ERRORS,    "Detected Errors"},
  {BPKM_VENDOR_DEFINED,     "Vendor Defined"},
  {0, NULL}
};

static const value_string error_code_vals[] = {
  {0, "No Information"},
  {1, "Unauthorized CM"},
  {2, "Unauthorized SAID"},
  {3, "Unsolicited"},
  {4, "Invalid Key Sequence Number"},
  {5, "Message (Key Request) authentication failure"},
  {6, "Permanent Authorization Failure"},
  {7, "Not authorized for requested downstream traffic flow"},
  {8, "Downstream traffic flow not mapped to SAID"},
  {9, "Time of day not acquired"},
  {10, "EAE Disabled"},
  {11, "BPI+ Version not supported"},
  {0, NULL},
};

static const value_string bpkm_crypto_suite_encr_vals[] = {
  {0x01, "CBC-Mode 56-bit DES"},
  {0x02, "CBC-Mode 40-bit DES"},
  {0x03, "CBC-Mode 128-bit AES"},
  {0x04, "CBC-Mode 256-bit AES"},
  {0, NULL}
};

static const value_string bpkm_crypto_suite_auth_vals[] = {
  {0x00, "No"},
  {0, NULL}
};

static const value_string bpkmattr_key_exchange_share_field_id_vals[] = {
  {0x0017, "secp256r1"},
  {0x0018, "secp384r1"},
  {0x0019, "secp521r1"},
  {0x001D, "x25519"},
  {0x001E, "x448"},
  {0, NULL}
};

static const value_string bpi_ver_vals[] = {
  {0, "Reserved"},
  {1, "BPI+ v1"},
  {2, "BPI+ v2"},
  {0, NULL}
};

static const value_string bpi_sa_vals[] = {
  {0, "Primary"},
  {1, "Static"},
  {2, "Dynamic"},
  {0, NULL}
};

static const range_string bpi_sa_query_type_vals[] = {
  {1, 1,     "IP Multicast"},
  {128, 255, "Vendor Specific"},
  {0, 0, NULL}
};

static const value_string bpkm_cmts_binding_vals[] = {
  {BPKMATTR_CMTS_DESIGNATION_CERTIFICATE_FINGERPRINT,  "Certificate Fingerprint"},
  {BPKMATTR_CMTS_DESIGNATION_COMMON_NAME,              "Common Name"},
  {BPKMATTR_CMTS_DESIGNATION_ORG_UNIT,                 "Organizational Unit"},
  {BPKMATTR_CMTS_DESIGNATION_ORG_NAME,                 "Organization Name"},
  {BPKMATTR_CMTS_DESIGNATION_SERIAL_NUMBER,            "Serial Number"},
  {BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_FINGERPRINT,   "Issuing CA Fingerprint"},
  {BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_COMMON_NAME,   "Issuing CA Common Name"},
  {BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_ORG_UNIT,      "Issuing CA Organizational Unit"},
  {BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_ORG_NAME,      "Issuing CA Organization Name"},
  {BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_SERIAL_NUMBER, "Issuing CA Serial Number"},
  {0, NULL}
};

static const value_string bpkm_cm_status_code_vals[] = {
  {0, "No error"},
  {1, "Generic error"},
  {2, "Auth Reply not received"},
  {3, "Missing Auth Reply required attribute"},
  {4, "BPI-Version mismatch"},
  {5, "NONCE mismatch"},
  {11, "Signature Format Error"},
  {12, "Signature Algorithm not supported"},
  {13, "Public Key Algorithm not supported"},
  {14, "Incomplete Certificate Chain"},
  {15, "Certificate Not Trusted"},
  {16, "Missing EE certificate revocation information"},
  {17, "Missing CA certificate revocation information"},
  {18, "EE certificate Expired"},
  {19, "CA certificate Expired"},
  {20, "CMTS-designation fingerprint (SHA-256) mismatch"},
  {21, "CMTS-designation Common-Name mismatch"},
  {22, "CMTS-designation Organizational-Unit mismatch"},
  {23, "CMTS-designation Organization-Name mismatch"},
  {24, "CMTS-designation Serial-Number mismatch"},
  {25, "CMTS-designation Issuing-CA-fingerprint (SHA-256) mismatch"},
  {26, "CMTS-designation Issuing-CA-Common-Name mismatch"},
  {27, "CMTS-designation Issuing-CA-Organizational-Unit mismatch"},
  {28, "CMTS-designation Issuing-CA-Organization mismatch"},
  {29, "CMTS-designation Issuing-CA-Serial-umber mismatch"},
  {30, "Missing Key-Derivation required parameters"},
  {31, "Key-Derivation parameters field mismatch"},
  {32, "Key-Derivation error"},
  {0, NULL}
};

static const value_string mdd_tlv_vals[] = {
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST,                       "Downstream Active Channel List"},
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP,                  "MAC Domain Downstream Service Group"},
  {DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST,       "Downstream Ambiguity Resolution Frequency List "},
  {RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL ,           "Receive Channel Profile Reporting Control"},
  {IP_INITIALIZATION_PARAMETERS ,                        "IP Initialization Parameters"},
  {EARLY_AUTHENTICATION_AND_ENCRYPTION ,                 "Early Authentication and Encryption"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST ,                        "Upstream Active Channel List"},
  {UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST ,          "Upstream Ambiguity Resolution Channel List"},
  {UPSTREAM_FREQUENCY_RANGE  ,                           "Upstream Frequency Range"},
  {SYMBOL_CLOCK_LOCKING_INDICATOR  ,                     "Symbol Clock Locking Indicator"},
  {CM_STATUS_EVENT_CONTROL  ,                            "CM-STATUS Event Control"},
  {UPSTREAM_TRANSMIT_POWER_REPORTING  ,                  "Upstream Transmit Power Reporting"},
  {DSG_DA_TO_DSID_ASSOCIATION_ENTRY  ,                   "DSG DA-to-DSID Association Entry"},
  {CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS  , "CM-STATUS Event Enable for Non-Channel-Specific-Events"},
  {EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT  ,           "Extended Upstream Transmit Power Support"},
  {CMTS_DOCSIS_VERSION  ,                                "CMTS DOCSIS Version"},
  {CM_PERIODIC_MAINTENANCE_TIMEOUT_INDICATOR  ,          "CM Periodic Maintenance Timeout Indicator"},
  {DLS_BROADCAST_AND_MULTICAST_DELIVERY_METHOD  ,        "DLS Broadcast and Multicast Delivery Method"},
  {CM_STATUS_EVENT_ENABLE_FOR_DOCSIS_3_1_EVENTS  ,       "CM-STATUS Event Enable for DOCSIS 3.1 Specific Events"},
  {DIPLEXER_BAND_EDGE  ,                                 "Diplexer Band Edge"},
  {ADVANCED_BAND_PLAN,                                   "Advanced Band Plan Descriptor"},
  {MDD_BPI_PLUS,                                         "BPI+ Enabled Version and Configuration"},
  {0, NULL}
};


static const value_string rcp_center_frequency_spacing_vals[] = {
  {ASSUME_6MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 6 MHz center frequency spacing"},
  {ASSUME_8MHZ_CENTER_FREQUENCY_SPACING  , "CM MUST report only Receive Channel Profiles assuming 8 MHz center frequency spacing"},
  {0, NULL}
};

static const value_string verbose_rcp_reporting_vals[] = {
  {RCP_NO_VERBOSE_REPORTING  , "CM MUST NOT provide verbose reporting of all its Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
  {RCP_VERBOSE_REPORTING  ,    "CM MUST provide verbose reporting of Receive Channel Profile(s) (both standard profiles and manufacturers profiles)."},
  {0, NULL}
};

static const value_string fragmented_rcp_transmission_vals[] = {
  {1, "CM optionally transmits Receive Channel Profile (s) requiring fragmentation (RCPs in excess of 255 bytes) in addition to those that do not."},
  {0, NULL}
};

static const value_string ip_provisioning_mode_vals[] = {
  {IPv4_ONLY  ,  "IPv4 Only"},
  {IPv6_ONLY ,   "IPv6 Only"},
  {IP_ALTERNATE, "Alternate"},
  {DUAL_STACK ,  "Dual Stack"},
  {0, NULL}
};

static const value_string eae_vals[] = {
  {EAE_DISABLED  , "early authentication and encryption disabled"},
  {EAE_ENABLED ,   "early authentication and encryption enabled"},
  {0, NULL}
};

static const value_string upstream_frequency_range_vals[] = {
  {STANDARD_UPSTREAM_FREQUENCY_RANGE, "Standard Upstream Frequency Range"},
  {EXTENDED_UPSTREAM_FREQUENCY_RANGE, "Extended Upstream Frequency Range"},
  {0, NULL}
};

static const value_string symbol_clock_locking_indicator_vals[] = {
  {NOT_LOCKED_TO_MASTER_CLOCK, "Symbol Clock is not locked to Master Clock"},
  {LOCKED_TO_MASTER_CLOCK,     "Symbol Clock is locked to Master Clock"},
  {0, NULL}
};

static const value_string symbol_cm_status_event_vals[] = {
  {SECONDARY_CHANNEL_MDD_TIMEOUT,               "Secondary Channel MDD timeout"},
  {QAM_FEC_LOCK_FAILURE,                        "Qam FEC Lock Failure"},
  {SEQUENCE_OUT_OF_RANGE,                       "Sequence out of Range"},
  {MDD_RECOVERY,                                "MDD Recovery"},
  {QAM_FEC_LOCK_RECOVERY,                       "Qam FEC Lock Recovery"},
  {T4_TIMEOUT,                                  "T4 Timeout"},
  {T3_RETRIES_EXCEEDED,                         "T3 Retries Exceeded"},
  {SUCCESFUL_RANGING_AFTER_T3_RETRIES_EXCEEDED, "Successful ranging after T3 Retries Exceeded"},
  {CM_OPERATING_ON_BATTERY_BACKUP,              "CM Operating on Battery Backup"},
  {CM_RETURNED_TO_AC_POWER,                     "CM Returned to AC Power"},
  {MAC_REMOVAL_EVENT,                           "MAC Removal Event"},
  {DS_OFDM_PROFILE_FAILURE,                     "DS OFDM Profile Failure"},
  {PRIMARY_DS_CHANGE,                           "Primary Downstream Change"},
  {DPD_MISMATCH,                                "DPD Mismatch"},
  {DEPRECATED,                                  "Deprecated"},
  {NCP_PROFILE_FAILURE,                         "NCP Profile Failure"},
  {PLC_FAILURE,                                 "PLC Failure"},
  {NCP_PROFILE_RECOVERY,                        "NCP Profile Recovery"},
  {PLC_RECOVERY,                                "PLC Recovery"},
  {OFDM_PROFILE_RECOVERY,                       "OFDM Profile Recovery"},
  {OFDMA_FAILURE,                               "OFDMA Failure"},
  {MAP_STORAGE_OVERFLOW,                        "MAP Storage Overflow"},
  {MAP_STORAGE_ALMOST_FULL,                     "MAP Storage Almost Full"},
  {0, NULL}
};

static const value_string upstream_transmit_power_reporting_vals[] = {
  {CM_DOESNT_REPORT_TRANSMIT_POWER, "CM does not report transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
  {CM_REPORTS_TRANSMIT_POWER,       "CM reports transmit power in RNG-REQ, INIT-RNG-REQ, and B-INIT-RNG-REQ messages"},
  {0, NULL}
};

static const value_string cm_periodic_maintenance_timeout_indicator_vals[] = {
  {0, "use Unicast Ranging opportunity"},
  {1, "use Probe opportunity"},
  {2, "use Unicast Ranging or Probe opportunity"},
  {0, NULL}
};

static const value_string dls_broadcast_and_multicast_delivery_method_vals[] = {
  {1, "delayed selected multicast method"},
  {2, "selectively replicated multicast method"},
  {0, NULL}
};


static const value_string mdd_ds_active_channel_list_vals[] = {
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID, "Channel ID"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY, "Frequency"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX, "Annex/Modulation Order"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE, "Primary Capable"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK, "CM-STATUS Event Enable Bitmask"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR, "MAP and UCD transport indicator"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS, "OFDM PLC Parameters"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_FDX_SUB_BAND_ID, "Full Duplex Sub-band ID"},
  {DOWNSTREAM_ACTIVE_CHANNEL_LIST_FDX_DS, "Full Duplex Downstream"},
  {0, NULL}
};

static const value_string mdd_ds_service_group_vals[] = {
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER, "MD-DS-SG Identifier"},
  {MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS,       "Channel Ids"},
  {0, NULL}
};

static const value_string mdd_channel_profile_reporting_control_vals[] = {
  {RCP_CENTER_FREQUENCY_SPACING, "RCP Center Frequency Spacing"},
  {VERBOSE_RCP_REPORTING,       "Verbose RCP reporting"},
  {FRAGMENTED_RCP_TRANSMISSION, "Fragmented RCP transmission"},
  {0, NULL}
};

static const value_string mdd_ip_init_param_vals[] = {
  {IP_PROVISIONING_MODE, "IP Provisioning Mode"},
  {PRE_REGISTRATION_DSID, "Pre-registration DSID"},
  {0, NULL}
};

static const value_string mdd_up_active_channel_list_vals[] = {
  {UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID, "Upstream Channel ID"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK, "CM-STATUS Event Enable Bitmask"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_PRIORITY, "Upstream Channel Priority"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST_DSCHIDS_MAPS_UCDS, "Downstream Channel(s) on which MAPs and UCDs for this Upstream Channel are sent"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST_FDX_UPSTREAM_CHANNEL, "FDX Upstream Channel"},
  {UPSTREAM_ACTIVE_CHANNEL_LIST_FDX_SUBBAND_ID, "FDX Sub-band ID"},
  {0, NULL}
};

static const value_string mdd_cm_status_event_control_vals[] = {
  {EVENT_TYPE_CODE, "Event Type"},
  {MAXIMUM_EVENT_HOLDOFF_TIMER,    "Maximum Event Holdoff Timer"},
  {MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT,    "Maximum Number of Reports per Event"},
  {0, NULL}
};

static const value_string mdd_cm_dsg_da_to_dsid_vals[] = {
  {DSG_DA_TO_DSID_ASSOCIATION_DA, "Destination Address"},
  {DSG_DA_TO_DSID_ASSOCIATION_DSID, "DSID"},
  {0, NULL}
};

static const value_string tlv20_vals[] = {
  {0, "Selectable active codes mode 1 enabled and code hopping disabled"},
  {1, "Selectable active codes mode 1 enabled and code hopping mode 1 enabled"},
  {2, "Selectable active codes mode 2 enabled and code hopping mode 2 enabled"},
  {3, "Selectable active codes mode 2 enabled and code hopping disabled"},
  {0, NULL}
};

static const value_string mdd_diplexer_band_edge_vals[] = {
  {DIPLEXER_US_UPPER_BAND_EDGE, "Diplexer Upstream Upper Band Edge"},
  {DIPLEXER_DS_LOWER_BAND_EDGE, "Diplexer Downstream Lower Band Edge"},
  {DIPLEXER_DS_UPPER_BAND_EDGE, "Diplexer Downstream Upper Band Edge"},
  {DIPLEXER_US_UPPER_BAND_EDGE_OVERRIDE, "Diplexer Upstream Upper Band Edge Override"},
  {DIPLEXER_DS_LOWER_BAND_EDGE_OVERRIDE, "Diplexer Downstream Lower Band Edge Override"},
  {DIPLEXER_DS_UPPER_BAND_EDGE_OVERRIDE, "Diplexer Downstream Upper Band Edge Override"},
  {0, NULL}
};

static const value_string mdd_diplexer_us_upper_band_edge_vals[] = {
  {0, "Upstream Frequency Range up to 42 MHz"},
  {1, "Upstream Frequency Range up to 65 MHz"},
  {2, "Upstream Frequency Range up to 85 MHz"},
  {3, "Upstream Frequency Range up to 117 MHz"},
  {4, "Upstream Frequency Range up to 204 MHz"},
  {0, NULL}
};

static const value_string mdd_diplexer_ds_lower_band_edge_vals[] = {
  {0, "Downstream Frequency Range starting from 108 MHz"},
  {1, "Downstream Frequency Range starting from 258 MHz"},
  {0, NULL}
};

static const value_string mdd_diplexer_ds_upper_band_edge_vals[] = {
  {0, "Downstream Frequency Range up to 1218 MHz"},
  {1, "Downstream Frequency Range up to 1794 MHz"},
  {2, "Downstream Frequency Range up to 1002 MHz"},
  {0, NULL}
};

static const value_string mdd_abp_vals[] = {
  {1, "Deprecated"},
  {MDD_ABP_SUB_BAND_COUNT, "Total number of sub-bands"},
  {MDD_ABP_SUB_BAND_WIDTH, "Full Duplex Sub-band Width"},
  {0, NULL}
};

static const value_string mdd_abp_sub_band_vals[] = {
  {0, "FDD Enabled"},
  {1, "1 FDX sub-band"},
  {2, "2 FDX sub-bands"},
  {3, "3 FDX sub-bands"},
  {0, NULL}
};

static const value_string mdd_abp_sub_band_width_vals[] = {
  {0, "96 MHz"},
  {1, "192 MHz"},
  {0, NULL}
};

static const value_string mdd_docsis_version_vals[] = {
  {CMTS_DOCSIS_VERSION_MAJOR_PRE_40, "CMTS Pre-DOCSIS 4.0 Major DOCSIS Version"},
  {CMTS_DOCSIS_VERSION_MINOR_PRE_40, "CMTS Pre-DOCSIS 4.0 Minor DOCSIS Version"},
  {CMTS_DOCSIS_VERSION_MAJOR, "CMTS Major DOCSIS Version"},
  {CMTS_DOCSIS_VERSION_MINOR, "CMTS Minor DOCSIS Version"},
  {CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE, "CMTS Extended Spectrum Mode of Operation"},
  {0, NULL}
};

static const value_string mdd_bpi_plus_vals[] = {
  {MDD_BPI_PLUS_VERSION, "BPI+ Version Number"},
  {MDD_BPI_PLUS_CFG, "BPI+ Configuration Bitmask"},
  {0, NULL}
};

static const value_string cmstatus_tlv_vals[] = {
  {STATUS_EVENT, "Status Event"},
  {0, NULL}
};

static const value_string cmstatus_status_event_tlv_vals[] = {
  {EVENT_DS_CH_ID, "Downstream Channel ID"},
  {EVENT_US_CH_ID, "Upstream Channel ID"},
  {EVENT_DSID, "DSID"},
  {EVENT_DESCR, "Description"},
  {EVENT_MAC_ADDRESS, "MAC Address"},
  {EVENT_DS_OFDM_PROFILE_ID, "Downstream OFDM Profile ID"},
  {EVENT_US_OFDMA_PROFILE_ID, "Upstream OFDMA Profile ID"},
  {0, NULL}
};

static const value_string cmctrlreq_tlv_vals[] = {
  {CM_CTRL_MUTE, "Upstream Channel RF Mute"},
  {CM_CTRL_MUTE_TIMEOUT, "RF Mute Timeout Interval"},
  {CM_CTRL_REINIT, "CM Reinitialize"},
  {CM_CTRL_DISABLE_FWD, "Disable Forwarding"},
  {CM_CTRL_DS_EVENT, "Override Downstream Events"},
  {CM_CTRL_US_EVENT, "Override Upstream Events"},
  {CM_CTRL_EVENT, "Override Non-Channel-Specific Events"},
  {0, NULL}
};

static const value_string cmctrlreq_us_tlv_vals[] = {
  {US_EVENT_CH_ID, "Upstream Channel ID"},
  {US_EVENT_MASK, "Upstream Status Event Enable Bitmask"},
  {0, NULL}
};

static const value_string cmctrlreq_ds_tlv_vals[] = {
  {DS_EVENT_CH_ID, "Downstream Channel ID"},
  {DS_EVENT_MASK,  "Downstream Status Event Enable Bitmask"},
  {0, NULL}
};

static const value_string emrsp_tlv_vals[] = {
  {EM_HOLDOFF_TIMER, "Hold-Off Timer"},
  {0, NULL}
};

static const value_string emreq_req_power_mode_vals[] = {
  {0, "Normal Operation"},
  {1, "Energy Management 1x1 Mode"},
  {2, "DOCSIS Light Sleep Mode"},
  {0, NULL}
};

static const value_string emrsp_rsp_code_vals[] = {
  {0, "OK"},
  {1, "Reject Temporary"},
  {2, "Reject Permanent, Requested Low Power Mode(s) Not Supported"},
  {3, "Reject Permanent, Requested Low Power Mode(s) Disabled"},
  {4, "Reject Permanent, Other"},
  {0, NULL}
};

static const value_string docsis_ocd_subc_assign_type_str[] = {
  {0, "range, continuous"},
  {1, "range, skip by 1"},
  {2, "list"},
  {3, "reserved"},
  {0, NULL}
};

static const value_string docsis_ocd_subc_assign_value_str[] = {
  {0, "specific value"},
  {1, "default value"},
  {0, NULL}
};

static const value_string docsis_ocd_subc_assign_subc_type_str[] = {
  {1, "continuous pilot"},
  {16, "excluded subcarriers"},
  {20, "PLC, 16-QAM"},
  {0, NULL}
};

static const value_string docsis_ocd_four_trans_size[] = {
  {0, "4096 subcarriers at 50 kHz spacing"},
  {1, "8192 subcarriers at 25 kHz spacing"},
  {0, NULL}
};

static const value_string docsis_ocd_cyc_prefix[] = {
  {0, "0.9375 "UTF8_MICRO_SIGN"s with 192 samples"},
  {1, "1.25 "UTF8_MICRO_SIGN"s with 256 samples"},
  {2, "2.5 "UTF8_MICRO_SIGN"s with 512 samples"},
  {3, "3.75 "UTF8_MICRO_SIGN"s with 768 samples"},
  {4, "5.0 "UTF8_MICRO_SIGN"s with 1024 samples"},
  {0, NULL}
};

static const value_string docsis_ocd_roll_off[] = {
  {0, "0 "UTF8_MICRO_SIGN"s with 0 samples"},
  {1, "0.3125 "UTF8_MICRO_SIGN"s with 64 samples"},
  {2, "0.625 "UTF8_MICRO_SIGN"s with 128 samples"},
  {3, "0.9375 "UTF8_MICRO_SIGN"s with 192 samples"},
  {4, "1.25 "UTF8_MICRO_SIGN"s with 256 samples"},
  {0, NULL}
};

static const value_string docsis_ocd_prim_cap_ind_str[] = {
  {0, "channel is not primary capable"},
  {1, "channel is primary capable"},
  {0, NULL}
};

static const value_string docsis_ocd_fdx_ind_str[] = {
  {1, "FDX Channel"},
  {0, NULL}
};

static const value_string ocd_tlv_vals[] = {
  {DISCRETE_FOURIER_TRANSFORM_SIZE, "Discrete Fourier Transform Size"},
  {CYCLIC_PREFIX, "Cyclic Prefix"},
  {ROLL_OFF, "Roll Off"},
  {OFDM_SPECTRUM_LOCATION, "OFDM Spectrum Location"},
  {TIME_INTERLEAVING_DEPTH, "Time Interleaving Depth"},
  {SUBCARRIER_ASSIGNMENT_RANGE_LIST, "Subcarrier Assignment Range/List"},
  {PRIMARY_CAPABILITY_INDICATOR, "Primary Capable Indicator"},
  {FDX_INDICATOR, "FDX Indicator"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_type_str[] = {
  {0, "range, continuous"},
  {1, "range, skip by 1"},
  {2, "list"},
  {3, "reserved"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_value_str[] = {
  {0, "specific value"},
  {1, "default value"},
  {0, NULL}
};

static const value_string docsis_dpd_subc_assign_modulation_str[] = {
  {0, "zero-bit loaded"},
  {1, "reserved"},
  {2, "QPSK (for NCP profile only)"},
  {3, "reserved"},
  {4, "16-QAM"},
  {5, "reserved"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {13, "8192-QAM"},
  {14, "16384-QAM"},
  {15, "reserved"},
  {0, NULL}
};

static const value_string docsis_dpd_tlv_subc_assign_vector_oddness_str[] = {
  {0, "N is even"},
  {1, "N is odd"},
  {0, NULL}
};

static const value_string docsis_dpd_tlv_subc_assign_vector_modulation_str[] = {
  {0, "zero-bit loaded"},
  {1, "continuous pilot"},
  {2, "QPSK (for NCP profile only)"},
  {3, "reserved"},
  {4, "16-QAM"},
  {5, "reserved"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {13, "8192-QAM"},
  {14, "16384-QAM"},
  {15, "reserved"},
  {0, NULL}
};

static const value_string dpd_tlv_vals[] = {
  {SUBCARRIER_ASSIGNMENT_RANGE_LIST, "Subcarrier Assignment Range/List"},
  {SUBCARRIER_ASSIGNMENT_VECTOR, "Subcarrier Assignment Vector"},
  {0, NULL}
};

static const value_string ofdma_cyclic_prefix_size_vals[] = {
  {1, "96 samples"},
  {2, "128 samples"},
  {3, "160 samples"},
  {4, "192 samples"},
  {5, "224 samples"},
  {6, "256 samples"},
  {7, "288 samples"},
  {8, "320 samples"},
  {9, "384 samples"},
  {10, "512 samples"},
  {11, "640 samples"},
  {0, NULL}
};

static const value_string ofdma_rolloff_period_size_vals[] = {
  {1, "0 samples"},
  {2, "32 samples"},
  {3, "64 samples"},
  {4, "96 samples"},
  {5, "128 samples"},
  {6, "160 samples"},
  {7, "192 samples"},
  {8, "224 samples"},
  {0, NULL}
};

static const value_string subc_spacing_vals[] = {
  {1, "25 kHz (corresponds to 4096 subcarriers and 16 subcarriers per minislot)"},
  {2, "50 kHz (corresponds to 2048 subcarriers and 8 subcarriers per minislot)"},
  {0, NULL}
};

static const value_string ofdma_prof_mod_order[] = {
  {0, "no bit-loading"},
  {1, "BPSK"},
  {2, "QPSK"},
  {3, "8-QAM"},
  {4, "16-QAM"},
  {5, "32-QAM"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {0, NULL}
};

static const value_string profile_id_vals[] = {
  {0, "Profile A"},
  {1, "Profile B"},
  {2, "Profile C"},
  {3, "Profile D"},
  {4, "Profile E"},
  {5, "Profile F"},
  {6, "Profile G"},
  {7, "Profile H"},
  {8, "Profile I"},
  {9, "Profile J"},
  {10, "Profile K"},
  {11, "Profile L"},
  {12, "Profile M"},
  {13, "Profile N"},
  {14, "Profile O"},
  {15, "Profile P"},
  {254, "Profile for RxMER statistics only"},
  {255, "NCP Profile"},
  {0, NULL}
};

static const value_string opt_opcode_vals[] = {
  {1, "Start"},
  {2, "Abort"},
  {3, "FDX Triggered Start"},
  {0, NULL}
};

static const value_string opt_status_vals[] = {
  {1, "Testing"},
  {2, "Profile already testing from another request"},
  {3, "No free profile resource on CM"},
  {4, "Maximum duration expired"},
  {5, "Aborted"},
  {6, "Complete"},
  {7, "Profile already assigned to the CM"},
  {8, "DS Lock Lost"},
  {0, NULL}
};

static const value_string optreq_tlv_vals[] = {
  {OPT_REQ_REQ_STAT, "Requested Statistics"},
  {OPT_REQ_RXMER_THRESH_PARAMS, "RxMER Thresholding Parameters"},
  {OPT_REQ_TRIGGER_DEFINITION, "Trigger Definition"},
  {0, NULL}
};

static const value_string optreq_tlv_rxmer_thresh_params_vals[] = {
  {OPT_REQ_RXMER_THRESH_PARAMS_MODULATION_ORDER, "Modulation Order"},
  {0, NULL}
};

static const value_string opreq_tlv_rxmer_thresh_params_mod_order[] = {
  {0, "reserved"},
  {1, "reserved"},
  {2, "QPSK"},
  {3, "reserved"},
  {4, "16-QAM"},
  {5, "reserved"},
  {6, "64-QAM"},
  {7, "128-QAM"},
  {8, "256-QAM"},
  {9, "512-QAM"},
  {10, "1024-QAM"},
  {11, "2048-QAM"},
  {12, "4096-QAM"},
  {13, "8192-QAM"},
  {14, "16384-QAM"},
  {15, "reserved"},
  {0, NULL}
};

static const value_string optreq_tlv_trigger_definition_vals[] = {
  {OPT_REQ_TRIGGER_DEFINITION_TRIGGER_TYPE, "Trigger Type"},
  {OPT_REQ_TRIGGER_DEFINITION_MEASUREMENT_DURATION, "Measurement Duration"},
  {OPT_REQ_TRIGGER_DEFINITION_TRIGGERING_SID, "Triggering SID"},
  {OPT_REQ_TRIGGER_DEFINITION_US_CHANNEL_ID, "US channel ID"},
  {OPT_REQ_TRIGGER_DEFINITION_OUDP_SOUND_AMBIG_OFFSET, "OUDP Sounding Ambiguity Offset"},
  {OPT_REQ_TRIGGER_DEFINITION_RXMER_TO_REPORT, "RxMER Measurement to Report"},
  {OPT_REQ_TRIGGER_DEFINITION_START_TIME, "Time-Triggered Start Time"},
  {0, NULL}
};

static const value_string optreq_tlv_triggered_definition_trigger_type_vals[] = {
  {0, "OUDP Sounding Triggered"},
  {1, "ECT RxMER Probe Triggered"},
  {2, "Time Triggered"},
  {0, NULL}
};

static const value_string optreq_tlv_triggered_definition_rx_mer_to_report_vals[] = {
  {0, "Report RxMER per Subcarrier for all subcarriers"},
  {1, "Report Average RxMER over all subcarriers"},
  {2, "Report both RxMER per Subcarrier and Average RxMER for all subcarriers"},
  {0, NULL}
};

static const value_string optrsp_tlv_vals [] = {
  {OPT_RSP_RXMER, "RxMER and SNR Margin Data"},
  {OPT_RSP_DATA_CW, "Data Profile Codeword Data"},
  {OPT_RSP_NCP_FIELDS, "NCP Fields Data"},
  {0, NULL}
};

static const value_string optrsp_rxmer_vals [] = {
  {OPT_RSP_RXMER_SUBCARRIER, "RxMER per Subcarrier"},
  {OPT_RSP_RXMER_SUBCARRIER_THRESHOLD, "RxMER per Subcarrier Threshold Comparison Result"},
  {OPT_RSP_RXMER_SUBCARRIER_THRESHOLD_COUNT, "Number of Subcarriers whose RxMER is RxMER Margin below the RxMER Target"},
  {OPT_RSP_RXMER_SNR_MARGIN, "SNR Margin"},
  {OPT_RSP_RXMER_AVG, "Average RxMER"},
  {OPT_RSP_RXMER_ECT_RBA_SUBBAND_DIRECTION, "ECT RxMER Probe-Triggered RBA Sub-band Direction Set"},
  {0, NULL}
};

static const value_string optrsp_data_cw_vals [] = {
  {OPT_RSP_DATA_CW_COUNT, "Codeword Count"},
  {OPT_RSP_DATA_CW_CORRECTED, "Corrected Codeword Count"},
  {OPT_RSP_DATA_CW_UNCORRECTABLE, "Uncorrectable Codeword Count"},
  {OPT_RSP_DATA_CW_THRESHOLD_COMPARISON, "Codeword Threshold Comparison Result for Candidate Profile"},
  {0, NULL}
};

static const value_string optrsp_data_cw_threshold_comparison_vals [] = {
  {0, "Uncorrectable Codeword Count (N_e) reached"},
  {1, "Codeword Count (N_c) reached"},
  {0, NULL}
};

static const value_string optrsp_ncp_fields_vals [] = {
  {OPT_RSP_NCP_FIELDS_COUNT, "NCP Fields Count"},
  {OPT_RSP_NCP_FIELDS_FAILURE, "NCP CRC Failure Count"},
  {OPT_RSP_NCP_FIELDS_THRESHOLD_COMPARISON, "NCP CRC Threshold Comparison Result"},
  {0, NULL}
};

static const value_string optrsp_ncp_fields_threshold_comparison_vals [] = {
  {0, "NCP CRC Failure Count (NF_e) reached"},
  {1, "NCP Fields Count (NF_c) reached"},
  {0, NULL}
};

static const value_string sid_field_bit15_14_vals [] = {
  {0, "No error condition"},
  {1, "Power Adjustment not applied"},
  {2, "The current value for Pr is more than 3dB below the top of the dynamic range window for all channels"},
  {3, "Maximum Scheduled Codes Unnecessary"},
  {0, NULL}
};

static const value_string rba_subband_direction_vals [] = {
  {0, "Downstream"},
  {1, "Upstream"},
  {2, "Undefined for this RBA"},
  {0, NULL}
};

static const value_string extended_us_channel_vals [] = {
  {0, "Channel is not an Extended Upstream Channel"},
  {1, "Channel is an Extended Upstream Channel"},
  {0, NULL}
};

static const value_string cwt_op_code_vals [] = {
  {1, "Start"},
  {2, "Stop"},
  {0, NULL}
};

static const value_string cwt_status_vals [] = {
  {1, "CWT-REQ accepted"},
  {2, "CWT-REQ rejected, invalid request"},
  {3, "CWT-REQ rejected, no-op"},
  {4, "CW aborted, transaction mismatch"},
  {5, "CW aborted, max duration timeout"},
  {0, NULL}
};
static const value_string cwt_tlv_vals [] = {
  {1, "Phase Rotation"},
  {2, "Maximum Duration"},
  {3, "Upstream Encodings"},
  {0, NULL}
};

static const value_string cwt_phase_rotation_vals [] = {
  {1, "pi/2"},
  {2, "2pi/3"},
  {3, "pi"},
  {0, NULL}
};

static const value_string cwt_us_encodings_tlv_vals [] = {
  {1, "Extended Upstream Channel ID"},
  {2, "Upstream Subcarrier Index"},
  {3, "Power Boost"},
  {0, NULL}
};

static void ect_trans_id_val(char *buf, uint16_t value)
{
  if (value == 255)
    snprintf(buf, ITEM_LABEL_LENGTH, "unsolicited ECT-RSP message");
  else
    snprintf(buf, ITEM_LABEL_LENGTH, "%d", value);
}

static const value_string ect_rsp_code_vals [] = {
  {0, "OK"},
  {1, "Reject, invalid parameters"},
  {2, "Reject, RBA not currently active"},
  {3, "Reject, Defer EC Training"},
  {0, NULL}
};

/* ECT TLVs */
static const value_string ect_tlv_vals [] = {
  {87, "Control Encodings"},
  {0, NULL}
};

/* TLV 87.* */
static const value_string ect_control_tlv_vals [] = {
  {1, "Sub-band Direction Set"},
  {2, "Training Status"},
  {3, "Training Method"},
  {4, "Partial Service Indicator"},
  {5, "Training Deferral Time"},
  {6, "RxMER Duration"},
  {0, NULL}
};

/* TLV 87.2 */
static const value_string ect_control_status_vals [] = {
  {0, "Converged"},
  {1, "Not yet converged"},
  {2, "No longer converged"},
  {3, "N/A"},
  {0, NULL}
};

/* TLV 87.3.* */
static const value_string ect_control_method_tlv_vals [] = {
  {1, "Foreground Training Parameters"},
  {2, "Background Training Parameters"},
  {3, "Training Method"},
  {4, "Partial Service Indicator"},
  {5, "Training Deferral Time"},
  {0, NULL}
};

/* TLV 87.3.1.* */
static const value_string ect_control_method_fg_tlv_vals [] = {
  {1, "Duration"},
  {2, "Periodicity"},
  {3, "Expiration Time"},
  {4, "Downstream Zero Bit Loading"},
  {0, NULL}
};

/* TLV 87.3.1.1, 8.6 */
static const unit_name_string units_symbols = { " symbol", " symbols" };

/* TLV 87.3.1.4 */
static const value_string ect_ds_zbl_vals [] = {
  {0, "Not required"},
  {1, "Required"},
  {0, NULL}
};

/* TLV 87.3.2.* */
static const value_string ect_control_method_bg_tlv_vals [] = {
  {1, "Duration"},
  {2, "Periodicity"},
  {3, "Expiration Time"},
  {4, "Window Start Time"},
  {0, NULL}
};

/* TLV 87.4.* */
static const value_string ect_control_partial_service_tlv_vals [] = {
  {1, "Downstream Channel List"},
  {2, "Upstream Channel List"},
  {0, NULL}
};

/* TLV 87.3.1.4 */
static void ect_deferral_time_val(char *buf, uint16_t value)
{
  switch(value)
  {
  case 0:
    snprintf(buf, ITEM_LABEL_LENGTH, "Next time the RBA sub-band direction set is active");
    break;
  case 1:
    snprintf(buf, ITEM_LABEL_LENGTH, "When the channel(s) in the RBA on which partial service occurred have recovered");
    break;
  default:
    snprintf(buf, ITEM_LABEL_LENGTH, "%d ms", value);
  }
}

static const range_string dpr_tg_id_vals [] = {
  {0x01, 0xff, "TG ID"},
  {0x00, 0x00, "All Transmission Groups"},
  {0, 0, NULL}
};

static const true_false_string tfs_ucd_change_ind_vals = {"Changes", "No changes"};

static const true_false_string tfs_allow_inhibit = { "Inhibit Initial Ranging", "Ranging Allowed" };
static const true_false_string type35ucd_tfs_present_not_present = { "UCD35 is present for this UCID",
                                                                     "UCD35 is not present for this UCID" };

static const true_false_string sid_field_bit15_tfs = {
  "The commanded power level P1.6r_n is higher than the value corresponding to the top of the DRW.",
  "The commanded power level P1.6r_n is not higher than the value corresponding to the top of the DRW."
};

static const true_false_string sid_field_bit14_tfs = {
  "The commanded power level P1.6r_n is in excess of 6 dB below the value corresponding to the top of the DRW.",
  "The commanded power level P1.6r_n is not in excess of 6 dB below the value corresponding to the top of the DRW."
};

static const value_string unique_unlimited[] = {
  { 0, "Unlimited" },
  {0, NULL}
};

static void
ofdma_ir_pow_ctrl_start_pow(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%.2f dBmV/1.6MHz", value/4.0);
}

static void
ofdma_ir_pow_ctrl_step_size(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%.2f dB", value/4.0);
}

static void
fourth_db(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%.2f dB", value/4.0);
}

static void
d30_time_ticks(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u 10.24 MHz time ticks (%.3f "UTF8_MICRO_SIGN"s)",
             value, value/10.24);
}

static void
subc_assign_range(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u - %u", value >> 16, value &0xFFFF);
}

static void
multipart_number_of_fragments(char *buf, uint32_t value)
{
    snprintf(buf, ITEM_LABEL_LENGTH, "%u (Actual Number of Fragments: %u)", value, value + 1);
}

/* table with an ID consisting of MMM Type as MSB and 3 type-specific LSB */
static reassembly_table docsis_tlv_reassembly_table;

static const fragment_items docsis_tlv_frag_items = {
  &ett_docsis_tlv_fragment,
  &ett_docsis_tlv_fragments,
  &hf_docsis_tlv_fragments,
  &hf_docsis_tlv_fragment,
  &hf_docsis_tlv_fragment_overlap,
  &hf_docsis_tlv_fragment_overlap_conflict,
  &hf_docsis_tlv_fragment_multiple_tails,
  &hf_docsis_tlv_fragment_too_long_fragment,
  &hf_docsis_tlv_fragment_error,
  &hf_docsis_tlv_fragment_count,
  &hf_docsis_tlv_reassembled_in,
  &hf_docsis_tlv_reassembled_length,
  &hf_docsis_tlv_reassembled_data,
  "TLV fragments"
};

static tvbuff_t *
dissect_multipart(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_,
                  const uint32_t mmm_type, uint32_t id, const int fixed_byte_count)
{
  /* Multipart MMM messages from version 5 onwards */
  unsigned version, multipart = 0, fragment, last_fragment, tlv_byte_count;
  address save_src, save_dst;

  version = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_docsis_mgmt, KEY_MGMT_VERSION));
  if (version > 4)
    multipart = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_docsis_mgmt, KEY_MGMT_MULTIPART));
  if (!multipart)
    return tvb_new_subset_remaining(tvb, fixed_byte_count);

  id += mmm_type << 24;
  fragment = multipart & 0x0F;
  last_fragment = multipart >> 4;
  tlv_byte_count = tvb_reported_length_remaining(tvb, fixed_byte_count);

  /* DOCSIS MAC management messages do not have network (IP) address. Use link (MAC) address instead. Same workflow as in wimax. */
  /* Save address pointers. */
  copy_address_shallow(&save_src, &pinfo->src);
  copy_address_shallow(&save_dst, &pinfo->dst);
  /* Use dl_src and dl_dst in defragmentation. */
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);

  fragment_head *fh = fragment_add_seq_check(&docsis_tlv_reassembly_table, tvb, fixed_byte_count, pinfo, id, NULL,
                                             fragment, tlv_byte_count, (fragment != last_fragment));

  /* Restore address pointers. */
  copy_address_shallow(&pinfo->src, &save_src);
  copy_address_shallow(&pinfo->dst, &save_dst);

  if (fh)
    return process_reassembled_data(tvb, fixed_byte_count, pinfo, "Reassembled TLVs", fh, &docsis_tlv_frag_items,
                                    NULL, tree);
  return NULL;
}

static int
dissect_sync (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *sync_tree;

  col_set_str(pinfo->cinfo, COL_INFO, "Sync Message");

  it = proto_tree_add_item(tree, proto_docsis_sync, tvb, 0, -1, ENC_NA);
  sync_tree = proto_item_add_subtree (it, ett_docsis_sync);

  proto_tree_add_item (sync_tree, hf_docsis_sync_cmts_timestamp, tvb, 0, 4, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static void
dissect_ucd_burst_descr(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, proto_item * item, int pos, uint16_t len)
{
  int tlvpos, endtlvpos;
  uint8_t tlvtype;
  uint32_t i, tlvlen;
  proto_tree *burst_tree;
  proto_item *burst_item, *burst_len_item;
  unsigned iuc;

  tlvpos = pos;
  endtlvpos = tlvpos + len;
  proto_tree_add_item_ret_uint (tree, hf_docsis_ucd_iuc, tvb, tlvpos++, 1, ENC_BIG_ENDIAN, &iuc);
  proto_item_append_text(item, ": IUC %d (%s)", iuc, val_to_str_const(iuc,iuc_vals, "Unknown IUC"));
  while (tlvpos < endtlvpos)
  {
    tlvtype = tvb_get_uint8 (tvb, tlvpos);
    burst_tree = proto_tree_add_subtree (tree, tvb, tlvpos, -1,
                                                        ett_docsis_burst_tlv, &burst_item,
                                                        val_to_str(tlvtype, burst_tlv_vals,
                                                        "Unknown TLV (%u)"));
    proto_tree_add_uint (burst_tree, hf_docsis_ucd_burst_type, tvb, tlvpos++, 1, tlvtype);
    burst_len_item = proto_tree_add_item_ret_uint (burst_tree, hf_docsis_ucd_burst_length, tvb, tlvpos++, 1, ENC_NA, &tlvlen);
    proto_item_set_len(burst_item, tlvlen + 2);
    switch (tlvtype)
    {
    case UCD_MODULATION:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_mod_type, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_DIFF_ENCODING:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_diff_encoding, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_PREAMBLE_LEN:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_preamble_len, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_PREAMBLE_VAL_OFF:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_preamble_val_off, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_FEC:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_fec, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_FEC_CODEWORD:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_fec_codeword, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCRAMBLER_SEED:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_scrambler_seed, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_MAX_BURST:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_max_burst, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_GUARD_TIME:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_guard_time, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_LAST_CW_LEN:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_last_cw_len, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCRAMBLER_ONOFF:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_burst_scrambler_onoff, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_RS_INT_DEPTH:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_rs_int_depth, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_RS_INT_BLOCK:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_rs_int_block, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_PREAMBLE_TYPE:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_preamble_type, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCMDA_SCRAMBLER_ONOFF:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_scdma_scrambler_onoff, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCDMA_CODES_PER_SUBFRAME:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_scdma_codes_per_subframe, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SCDMA_FRAMER_INT_STEP_SIZE:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_scdma_framer_int_step_size, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_TCM_ENABLED:
      if (tlvlen == 1)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ucd_tcm_enabled, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SUBC_INIT_RANG:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_subc_init_rang, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_SUBC_FINE_RANG:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_subc_fine_rang, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case UCD_OFDMA_PROFILE:
      if ((tlvlen % 2) == 0)
      {
        for(i =0; i < tlvlen; i+=2) {
          proto_tree_add_item (burst_tree, hf_docsis_ofdma_prof_mod_order, tvb, tlvpos + i, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item (burst_tree, hf_docsis_ofdma_prof_pilot_pattern, tvb, tlvpos + i, 1, ENC_BIG_ENDIAN);
          proto_tree_add_item (burst_tree, hf_docsis_ofdma_prof_num_add_minislots, tvb, tlvpos + i + 1, 1, ENC_BIG_ENDIAN);
        }
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u (even length expected)", tlvlen);
      }
      break;
    case UCD_OFDMA_IR_POWER_CONTROL:
      if (tlvlen == 2)
      {
        proto_tree_add_item (burst_tree, hf_docsis_ofdma_ir_pow_ctrl_start_pow, tvb, tlvpos, tlvlen, ENC_BIG_ENDIAN);
        proto_tree_add_item (burst_tree, hf_docsis_ofdma_ir_pow_ctrl_step_size, tvb, tlvpos + 1, tlvlen, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, burst_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;

    } /* switch(tlvtype) */

  tlvpos += tlvlen;
  } /* while (tlvpos < endtlvpos) */

}

static int
dissect_any_ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int proto_id, int type_number)
{
  int pos;
  uint32_t i, upchid, length;
  uint8_t type, symrate;
  proto_tree *ucd_tree, *tlv_tree;
  proto_item *ucd_item, *tlv_item, *tlv_len_item;

  ucd_item = proto_tree_add_item(tree, proto_id, tvb, 0, -1, ENC_NA);
  ucd_tree = proto_item_add_subtree (ucd_item, ett_docsis_ucd);
  proto_tree_add_item_ret_uint (ucd_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &upchid);
  proto_tree_add_item (ucd_tree, hf_docsis_ucd_config_ch_cnt, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (ucd_tree, hf_docsis_ucd_mini_slot_size, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (ucd_tree, hf_docsis_mgt_down_chid, tvb, 3, 1, ENC_BIG_ENDIAN);

  /* if the upstream Channel ID is 0 then this is for Telephony Return) */
  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type %d UCD Message: Channel ID = %u (U%u)", type_number, upchid,
                  upchid - 1);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Type %d UCD Message: Channel ID = %u (Telephony Return)",
                  type_number, upchid);

  pos = 4;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(ucd_tree, tvb, pos, -1,
                                            ett_docsis_tlv, &tlv_item,
                                            val_to_str(type, channel_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_ucd_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_ucd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case UCD_SYMBOL_RATE:
      if (length == 1)
      {
        symrate = tvb_get_uint8 (tvb, pos);
        proto_tree_add_uint (tlv_tree, hf_docsis_ucd_symbol_rate, tvb, pos, length, symrate * 160);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_FREQUENCY:
      if (length == 4)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_frequency, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_PREAMBLE:
      proto_tree_add_item (tlv_tree, hf_docsis_ucd_preamble_pat, tvb, pos, length, ENC_NA);
      break;
    case UCD_BURST_DESCR:
    case UCD_BURST_DESCR5: /* DOCSIS 2.0 Upstream Channel Descriptor */
    case UCD_BURST_DESCR23:
      dissect_ucd_burst_descr(tvb, pinfo, tlv_tree, tlv_item, pos, length);
      break;
    case UCD_EXT_PREAMBLE:
      proto_tree_add_item (tlv_tree, hf_docsis_ucd_ext_preamble_pat, tvb, pos, length, ENC_NA);
      break;
    case UCD_SCDMA_MODE_ENABLED:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_mode_enabled, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_SPREADING_INTERVAL:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_spreading_interval, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_CODES_PER_MINI_SLOT:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_codes_per_mini_slot, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_ACTIVE_CODES:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_active_codes, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_CODE_HOPPING_SEED:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_code_hopping_seed, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_US_RATIO_NUM:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_us_ratio_num, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_US_RATIO_DENOM:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_us_ratio_denom, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_TIMESTAMP_SNAPSHOT:
      if (length == 9)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_timestamp_snapshot, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_MAINTAIN_POWER_SPECTRAL_DENSITY:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_maintain_power_spectral_density, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RANGING_REQUIRED:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ranging_required, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_MAX_SCHEDULED_CODES:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_max_scheduled_codes, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RANGING_HOLD_OFF_PRIORITY_FIELD:
      if (length == 4)
      {
        static int * const ucd_rnghoff[] = {
          &hf_docsis_ucd_rnghoff_cm,
          &hf_docsis_ucd_rnghoff_erouter,
          &hf_docsis_ucd_rnghoff_emta,
          &hf_docsis_ucd_rnghoff_estb,
          &hf_docsis_ucd_rnghoff_rsvd,
          &hf_docsis_ucd_rnghoff_id_ext,
          NULL
        };

        proto_tree_add_bitmask_list(tlv_tree, tvb, pos, length, ucd_rnghoff, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RANGING_CHANNEL_CLASS_ID:
      if (length == 4)
      {
        static int * const ucd_chan_class_id[] = {
          &hf_docsis_ucd_chan_class_id_cm,
          &hf_docsis_ucd_chan_class_id_erouter,
          &hf_docsis_ucd_chan_class_id_emta,
          &hf_docsis_ucd_chan_class_id_estb,
          &hf_docsis_ucd_chan_class_id_rsvd,
          &hf_docsis_ucd_chan_class_id_id_ext,
          NULL
        };

        proto_tree_add_bitmask_list(tlv_tree, tvb, pos, length, ucd_chan_class_id, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_SELECTION_ACTIVE_CODES_AND_CODE_HOPPING:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_active_code_hopping, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SCDMA_SELECTION_STRING_FOR_ACTIVE_CODES:
      if (length == 16)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_scdma_selection_active_codes, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_HIGHER_UCD_FOR_SAME_UCID:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_higher_ucd_for_same_ucid, tvb, pos, length, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_higher_ucd_for_same_ucid_resv, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_CHANGE_IND_BITMASK:
      if (length == 2)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_subc_excl_band, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_unused_subc, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_other_subc, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc5, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc6, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc9, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc10, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc11, tvb, pos + 1, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc12, tvb, pos, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc13, tvb, pos, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc3_or_4, tvb, pos, 1, ENC_NA);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_change_ind_bitmask_reserved, tvb, pos, 1, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_OFDMA_TIMESTAMP_SNAPSHOT:
      if (length == 9)
      {
        static int* const timestamp_snapshot_parts[] = {
          &hf_docsis_ucd_ofdma_timestamp_snapshot_reserved,
          &hf_docsis_ucd_ofdma_timestamp_snapshot_d30timestamp,
          &hf_docsis_ucd_ofdma_timestamp_snapshot_4msbits_of_div20,
          NULL
        };
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ofdma_timestamp_snapshot, tvb, pos, length, ENC_NA);
        proto_tree_add_bitmask_list(tlv_tree, tvb, pos, 5, timestamp_snapshot_parts, ENC_BIG_ENDIAN);
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ofdma_timestamp_snapshot_minislot_count, tvb, pos+5, length-5, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_OFDMA_CYCLIC_PREFIX_SIZE:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ofdma_cyclic_prefix_size, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_OFDMA_ROLLOFF_PERIOD_SIZE:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_ofdma_rolloff_period_size, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SUBCARRIER_SPACING:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_subc_spacing, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_CENTER_FREQ_SUBC_0:
      if (length == 4)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_cent_freq_subc0, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SUBC_EXCL_BAND:
      if ((length % 4) == 0)
      {
        for(i = 0; i < length; i+=4) {
          proto_tree_add_item (tlv_tree, hf_docsis_ucd_subcarrier_range, tvb, pos+i, 4, ENC_NA);
        }
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_UNUSED_SUBC_SPEC:
      if ((length % 4) == 0)
      {
        for(i = 0; i < length; i+=4) {
          proto_tree_add_item (tlv_tree, hf_docsis_ucd_subcarrier_range, tvb, pos+i, 4, ENC_NA);
        }
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_SYMB_IN_OFDMA_FRAME:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_symb_ofdma_frame, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case UCD_RAND_SEED:
      if (length == 3)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_rand_seed, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case EXTENDED_US_CHANNEL:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_ucd_extended_us_channel, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }    /* switch(type) */
    pos += length;
  }      /* tvb_reported_length_remaining(tvb, pos) > 0 */

  return tvb_captured_length(tvb);
}

static int
dissect_ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_ucd, MGT_UCD);
}

static int
dissect_any_map (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, uint8_t version, void* data _U_)
{
  uint32_t i, numie, upchid, ucd_count, cat = 0, ie;
  int pos;
  proto_item *it;
  proto_tree *map_tree;
  static int * const ies[] = {
    &hf_docsis_map_sid,
    &hf_docsis_map_iuc,
    &hf_docsis_map_offset,
    NULL
  };

  static int * const probe_ies[] = {
    &hf_docsis_map_sid,
    &hf_docsis_map_mer,
    &hf_docsis_map_pw,
    &hf_docsis_map_eq,
    &hf_docsis_map_st,
    &hf_docsis_map_probe_frame,
    &hf_docsis_map_symbol_in_frame,
    &hf_docsis_map_start_subc,
    &hf_docsis_map_subc_skip,
    NULL
  };

  static int * const probe_ies_ect[] = {
    &hf_docsis_map_sid,
    &hf_docsis_map_mer,
    &hf_docsis_map_pw,
    &hf_docsis_map_eq,
    &hf_docsis_map_st,
    &hf_docsis_map_probe_frame,
    &hf_docsis_map_symbol_in_frame,
    &hf_docsis_map_start_subc,
    &hf_docsis_map_ect,
    NULL
  };

  switch (version) {
    case 1:
      it = proto_tree_add_item(tree, proto_docsis_map_v1, tvb, 0, -1, ENC_NA);
      break;
    case 5:
      it = proto_tree_add_item(tree, proto_docsis_map_v5, tvb, 0, -1, ENC_NA);
      break;
    default:
      it = proto_tree_add_item(tree, proto_docsis_map_v1, tvb, 0, -1, ENC_NA);
      expert_add_info_format(pinfo, it, &ei_docsis_mgmt_version_unknown, "Unknown MAP MAC Management version: %u", version);
      return tvb_captured_length(tvb);
  }

  map_tree = proto_item_add_subtree (it, ett_docsis_map);

  proto_tree_add_item_ret_uint (map_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &upchid);
  proto_tree_add_item_ret_uint (map_tree, hf_docsis_map_ucd_count, tvb, 1, 1, ENC_BIG_ENDIAN, &ucd_count);
  switch (version) {
    case 1:
      proto_tree_add_item_ret_uint (map_tree, hf_docsis_map_numie, tvb, 2, 1, ENC_BIG_ENDIAN, &numie);
      proto_tree_add_item (map_tree, hf_docsis_map_rsvd, tvb, 3, 1, ENC_BIG_ENDIAN);
      break;
    case 5:
      proto_tree_add_item_ret_uint (map_tree, hf_docsis_map_numie_v5, tvb, 2, 2, ENC_BIG_ENDIAN, &numie);
      proto_tree_add_item (map_tree, hf_docsis_map_rsvd_v5, tvb, 3, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item_ret_uint (map_tree, hf_docsis_map_cat, tvb, 3, 1, ENC_BIG_ENDIAN, &cat);
      break;
    default:
      it = proto_tree_add_item(tree, proto_docsis_map_v1, tvb, 0, -1, ENC_NA);
      expert_add_info_format(pinfo, it, &ei_docsis_mgmt_version_unknown, "Unknown MAP MAC Management version: %u", version);
      return tvb_captured_length(tvb);
  }

  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Map Message:  Version: %d, Channel ID = %u (U%u), UCD Count = %u,  # IE's = %u",
                  version, upchid, upchid - 1, ucd_count, numie);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Map Message:  Version: %d, Channel ID = %u (Telephony Return), UCD Count = %u, # IE's = %u",
                  version, upchid, ucd_count, numie);

  proto_tree_add_item (map_tree, hf_docsis_map_alloc_start, tvb, 4, 4, ENC_BIG_ENDIAN);
  if (cat == 0) {
    proto_tree_add_item (map_tree, hf_docsis_map_ack_time, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item (map_tree, hf_docsis_map_rng_start, tvb, 12, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (map_tree, hf_docsis_map_rng_end, tvb, 13, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (map_tree, hf_docsis_map_data_start, tvb, 14, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (map_tree, hf_docsis_map_data_end, tvb, 15, 1, ENC_BIG_ENDIAN);

    pos = 16;
    for (i = 0; i < numie; i++)
    {
      proto_tree_add_bitmask_with_flags(map_tree, tvb, pos, hf_docsis_map_ie, ett_docsis_map_ie, ies, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
      pos = pos + 4;
    }
  }
  if (cat == 1) {
    pos = 8;
    for (i = 0; i < numie; i++)
    {
      ie = tvb_get_uint32(tvb, pos, ENC_BIG_ENDIAN);
      if ((ie & (MAP_PROBE_IE_PW_MASK | MAP_PROBE_IE_ST_MASK)) == 0)
        proto_tree_add_bitmask_with_flags(map_tree, tvb, pos, hf_docsis_map_probe_ie, ett_docsis_map_probe_ie, probe_ies_ect, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
      else
        proto_tree_add_bitmask_with_flags(map_tree, tvb, pos, hf_docsis_map_probe_ie, ett_docsis_map_probe_ie, probe_ies, ENC_BIG_ENDIAN, BMT_NO_FLAGS);
      pos = pos + 4;
    }
  }

  return tvb_captured_length(tvb);
}


static int dissect_map_v1 (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_) {
  return dissect_any_map(tvb, pinfo, tree, MAP_v1, data);
}

static int dissect_map_v5 (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_) {
  return dissect_any_map(tvb, pinfo, tree, MAP_v5, data);
}

static int
dissect_rngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *rngreq_tree;
  uint32_t sid;
  uint8_t version;

  it = proto_tree_add_item(tree, proto_docsis_rngreq, tvb, 0, -1, ENC_NA);
  rngreq_tree = proto_item_add_subtree (it, ett_docsis_rngreq);

  version = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_docsis_mgmt, KEY_MGMT_VERSION));
  if (version == 1) {
    proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_sid_field_bit15_14, tvb, 0, 1, ENC_BIG_ENDIAN);
  }
  if (version == 5) {
    //RNG-REQ sent to 3.1 CMTS
    proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_sid_field_bit15, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_sid_field_bit14, tvb, 0, 1, ENC_BIG_ENDIAN);
  }
  proto_tree_add_item_ret_uint (rngreq_tree, hf_docsis_rngreq_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);

  if (sid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO, "Ranging Request: SID = %u",
                      sid);
  else
    col_set_str(pinfo->cinfo, COL_INFO, "Initial Ranging Request SID = 0");

  proto_tree_add_item (rngreq_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (rngreq_tree, hf_docsis_rngreq_pend_compl, tvb, 3, 1, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static void
dissect_rngrsp_transmit_equalization_encodings_scdma_tdma(tvbuff_t * tvb, proto_item * it, unsigned start, uint16_t len)
{
  uint16_t i;
  proto_tree *transmit_equalization_encodings_tree, *coef_tree;

  transmit_equalization_encodings_tree = proto_item_add_subtree (it, ett_docsis_rngrsp_tlv_transmit_equalization_encodings);

  proto_tree_add_item (transmit_equalization_encodings_tree, hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_main_tap_location, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (transmit_equalization_encodings_tree, hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_number_of_forward_taps_per_symbol, tvb, start + 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (transmit_equalization_encodings_tree, hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_number_of_forward_taps_n, tvb, start + 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (transmit_equalization_encodings_tree, hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_reserved, tvb, start + 3, 1, ENC_BIG_ENDIAN);

  for(i=4; i < len; i+=4) {
    int real, imag;
    coef_tree = proto_tree_add_subtree_format (transmit_equalization_encodings_tree, tvb, start + i, 4, ett_docsis_rngrsp_tlv_transmit_equalization_encodings_coef, NULL, "Tap %d: ", i/4);
    proto_tree_add_item_ret_int (coef_tree, hf_docsis_rngrsp_trans_eq_enc_coef_real, tvb, start + i, 2, ENC_BIG_ENDIAN, &real);
    proto_tree_add_item_ret_int (coef_tree, hf_docsis_rngrsp_trans_eq_enc_coef_imag, tvb, start + i + 2, 2, ENC_BIG_ENDIAN, &imag);
    proto_item_append_text(coef_tree, "real: %f, imag: %f", (int16_t) real/16384.0, (int16_t) imag/16384.0);
  }
}

static void
dissect_rngrsp_transmit_equalization_encodings_ofdma(tvbuff_t * tvb, proto_tree * tree, unsigned start, uint16_t len)
{
  uint16_t i;
  proto_item *it;
  proto_tree *transmit_equalization_encodings_tree, *coef_tree;
  unsigned lowest_subc;

  it = proto_tree_add_item(tree, hf_docsis_rngrsp_trans_eq_data, tvb, start, len, ENC_NA);
  transmit_equalization_encodings_tree = proto_item_add_subtree (it, ett_docsis_rngrsp_tlv_transmit_equalization_encodings);

  proto_tree_add_item_ret_uint (transmit_equalization_encodings_tree, hf_docsis_rngrsp_trans_eq_enc_lowest_subc, tvb, start, 3, ENC_BIG_ENDIAN, &lowest_subc);
  proto_tree_add_item (transmit_equalization_encodings_tree, hf_docsis_rngrsp_trans_eq_enc_highest_subc, tvb, start, 3, ENC_BIG_ENDIAN);
  for(i=3; i < len; i+=4) {
    int real, imag;
    coef_tree = proto_tree_add_subtree_format (transmit_equalization_encodings_tree, tvb, start + i, 4, ett_docsis_rngrsp_tlv_transmit_equalization_encodings_coef, NULL, "Subcarrier %d: ", lowest_subc + (i-3)/4);
    proto_tree_add_item_ret_int (coef_tree, hf_docsis_rngrsp_trans_eq_enc_coef_real, tvb, start + i, 2, ENC_BIG_ENDIAN, &real);
    proto_tree_add_item_ret_int (coef_tree, hf_docsis_rngrsp_trans_eq_enc_coef_imag, tvb, start + i + 2, 2, ENC_BIG_ENDIAN, &imag);
    proto_item_append_text(coef_tree, "real: %f, imag: %f", (int16_t) real/16384.0, (int16_t) imag/16384.0);
  }
}

static void
dissect_rngrsp_commanded_power(tvbuff_t * tvb, proto_tree * tree, unsigned start, uint16_t len)
{
  uint16_t pos;
  uint16_t i;
  uint8_t tlvtype, tlvlen;
  proto_item *it;
  proto_tree *commanded_power_tree;
  proto_tree *commanded_power_subtlv_tree;
  proto_item *rngrsptlv_commanded_power_subtlv;


  it = proto_tree_add_item(tree, hf_docsis_rngrsp_commanded_power_data, tvb, start-2, len+2, ENC_NA);
  commanded_power_tree = proto_item_add_subtree (it, ett_docsis_rngrsp_tlv_commanded_power);


  pos = start;
  while (pos < start + len)
  {
    tlvtype = tvb_get_uint8 (tvb, pos);
    commanded_power_subtlv_tree = proto_tree_add_subtree(commanded_power_tree, tvb, pos, -1,
                                  ett_docsis_rngrsp_tlv_commanded_power_subtlv, &rngrsptlv_commanded_power_subtlv,
                                  val_to_str(tlvtype, rngrsp_tlv_commanded_power_subtlv_vals,
                                  "Unknown TLV (%u)"));
    pos++;
    tlvlen = tvb_get_uint8 (tvb, pos);
    pos++;

    switch (tlvtype)
    {
      case RNGRSP_COMMANDED_POWER_DYNAMIC_RANGE_WINDOW:
        if (tlvlen == 1)
        {
          proto_tree_add_item (commanded_power_subtlv_tree,
                                    hf_docsis_rngrsp_commanded_power_dynamic_range_window, tvb, pos,
                                    tlvlen, ENC_BIG_ENDIAN);
        }
        break;
      case RNGRSP_COMMANDED_POWER_UCID_AND_POWER_LEVEL_LIST:
        if ((tlvlen %3)== 0)
        {
          for(i=0; i < tlvlen; i+=3)
          {
             proto_tree_add_item (commanded_power_subtlv_tree,
                                      hf_docsis_rngrsp_commanded_power_ucid, tvb, pos + i,
                                      1, ENC_BIG_ENDIAN);
             proto_tree_add_item (commanded_power_subtlv_tree,
                                      hf_docsis_rngrsp_commanded_power_trans_pow_lvl, tvb, pos + i +1,
                                      2, ENC_BIG_ENDIAN);
          }
        }
        break;
      }
      pos += tlvlen;
  }
}

static void
dissect_rngrsp_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * rngrsp_tree)
{
  proto_item *rngrsptlv_item, *it;
  proto_tree *rngrsptlv_tree;
  unsigned pos = 0;
  unsigned tlvlen;
  uint8_t tlvtype;


  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    tlvtype = tvb_get_uint8 (tvb, pos);
    rngrsptlv_tree = proto_tree_add_subtree(rngrsp_tree, tvb, pos, -1,
                                  ett_docsis_rngrsptlv, &rngrsptlv_item,
                                  val_to_str(tlvtype, rngrsp_tlv_vals,
                                  "Unknown TLV (%u)"));
    proto_tree_add_uint (rngrsptlv_tree, hf_docsis_rngrsp_type, tvb, pos, 1, tlvtype);
    pos++;
    tlvlen = tvb_get_uint8 (tvb, pos);
    if  (tlvtype == RNGRSP_TRANSMIT_EQ_ADJUST_OFDMA_CHANNELS || tlvtype == RNGRSP_TRANSMIT_EQ_SET_OFDMA_CHANNELS) {
      proto_tree_add_item_ret_uint (rngrsptlv_tree, hf_docsis_rngrsp_length, tvb, pos, 2, ENC_NA, &tlvlen);
      pos += 2;
    } else {
      proto_tree_add_item_ret_uint (rngrsptlv_tree, hf_docsis_rngrsp_length, tvb, pos, 1, ENC_NA, &tlvlen);
      pos++;
    }
    proto_item_set_len(rngrsptlv_item, tlvlen + 2);
    switch (tlvtype)
    {
    case RNGRSP_TIMING:
      if (tlvlen == 4)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_timing_adj, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_PWR_LEVEL_ADJ:
      if (tlvlen == 1)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_power_adj, tvb, pos, tlvlen, ENC_NA);
      }
      break;
    case RNGRSP_OFFSET_FREQ_ADJ:
      if (tlvlen == 2)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_freq_adj, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_TRANSMIT_EQ_ADJ:
      it = proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_xmit_eq_adj, tvb, pos, tlvlen, ENC_NA);
      dissect_rngrsp_transmit_equalization_encodings_scdma_tdma(tvb, it, pos, tlvlen);
      break;
    case RNGRSP_RANGING_STATUS:
      if (tlvlen == 1)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_ranging_status, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_DOWN_FREQ_OVER:
      if (tlvlen == 4)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_down_freq_over, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_UP_CHID_OVER:
      if (tlvlen == 1)
      {
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_upstream_ch_over, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      }
      break;
    case RNGRSP_TRANSMIT_EQ_SET:
      it = proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_xmit_eq_set, tvb, pos, tlvlen, ENC_NA);
      dissect_rngrsp_transmit_equalization_encodings_scdma_tdma(tvb, it, pos, tlvlen);
      break;
    case RNGRSP_T4_TIMEOUT_MULTIPLIER:
      if (tlvlen == 1)
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_rngrsp_t4_timeout_multiplier, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      else
      {
        expert_add_info_format(pinfo, rngrsptlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case RNGRSP_DYNAMIC_RANGE_WINDOW_UPPER_EDGE:
      if (tlvlen == 1)
        proto_tree_add_item (rngrsptlv_tree, hf_docsis_rngrsp_dynamic_range_window_upper_edge, tvb, pos, tlvlen, ENC_BIG_ENDIAN);
      else
      {
        expert_add_info_format(pinfo, rngrsptlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", tlvlen);
      }
      break;
    case RNGRSP_TRANSMIT_EQ_ADJUST_OFDMA_CHANNELS:
      dissect_rngrsp_transmit_equalization_encodings_ofdma(tvb, rngrsptlv_tree, pos, tlvlen);
      break;
    case RNGRSP_TRANSMIT_EQ_SET_OFDMA_CHANNELS:
      dissect_rngrsp_transmit_equalization_encodings_ofdma(tvb, rngrsptlv_tree, pos, tlvlen);
      break;
    case RNGRSP_COMMANDED_POWER:
    case RNGRSP_EXT_US_COMMANDED_POWER:
      dissect_rngrsp_commanded_power(tvb, rngrsptlv_tree, pos, tlvlen);
      break;

    default:
       proto_tree_add_item (rngrsp_tree, hf_docsis_rngrsp_tlv_unknown, tvb, pos, tlvlen, ENC_NA);
    }                   /* switch(tlvtype) */
    pos += tlvlen;
  }                       /* while (tvb_reported_length_remaining(tvb, pos) > 0) */
}

static int
dissect_rngrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *rngrsp_tree;
  tvbuff_t *tlv_tvb = NULL;
  uint32_t sid, upchid, id;

  it = proto_tree_add_item(tree, proto_docsis_rngrsp, tvb, 0, -1, ENC_NA);
  rngrsp_tree = proto_item_add_subtree (it, ett_docsis_rngrsp);

  proto_tree_add_item_ret_uint (rngrsp_tree, hf_docsis_rngrsp_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item_ret_uint (rngrsp_tree, hf_docsis_mgt_upstream_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &upchid);

  if (upchid > 0)
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Ranging Response: SID = %u, Upstream Channel = %u (U%u)",
                  sid, upchid, upchid - 1);
  else
    col_add_fstr (pinfo->cinfo, COL_INFO,
                  "Ranging Response: SID = %u, Telephony Return", sid);


  id = (upchid << 16) + sid;
  tlv_tvb = dissect_multipart(tvb, pinfo, rngrsp_tree, data, MGT_RNG_RSP, id, 3);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_rngrsp_tlv(tlv_tvb, pinfo, rngrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regreq_tree;
  uint32_t sid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_regreq, tvb, 0, -1, ENC_NA);
  regreq_tree = proto_item_add_subtree (it, ett_docsis_regreq);

  proto_tree_add_item_ret_uint (regreq_tree, hf_docsis_regreq_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);

  col_add_fstr (pinfo->cinfo, COL_INFO, "Registration Request SID = %u", sid);

  /* Call Dissector for Appendix C TlV's */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regrsp_tree;
  uint32_t sid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_regrsp, tvb, 0, -1, ENC_NA);
  regrsp_tree = proto_item_add_subtree (it, ett_docsis_regrsp);
  proto_tree_add_item_ret_uint (regrsp_tree, hf_docsis_regrsp_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item_ret_uint (regrsp_tree, hf_docsis_regrsp_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Registration Response SID = %u (%s)", sid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_uccreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *uccreq_tree;
  uint32_t chid;

  it = proto_tree_add_item (tree, proto_docsis_uccreq, tvb, 0, -1, ENC_NA);
  uccreq_tree = proto_item_add_subtree (it, ett_docsis_uccreq);

  proto_tree_add_item_ret_uint (uccreq_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &chid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Upstream Channel Change request: Channel ID = %u (U%u)",
                chid, (chid > 0 ? chid - 1 : chid));

  return tvb_captured_length(tvb);
}

static int
dissect_uccrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *uccrsp_tree;
  uint32_t chid;

  it = proto_tree_add_item(tree, proto_docsis_uccrsp, tvb, 0, -1, ENC_NA);
  uccrsp_tree = proto_item_add_subtree (it, ett_docsis_uccrsp);

  proto_tree_add_item_ret_uint (uccrsp_tree, hf_docsis_mgt_upstream_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &chid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Upstream Channel Change response: Channel ID = %u (U%u)",
                chid, (chid > 0 ? chid - 1 : chid));

  return tvb_captured_length(tvb);
}

/* The dissect_attrs() function does the actual work to dissect the
 * attributes.  It's called recursively, to dissect embedded attributes
 */
static void
// NOLINTNEXTLINE(misc-no-recursion)
dissect_attrs(tvbuff_t * tvb, packet_info * pinfo, proto_item *item _U_, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item, *tlv_subitem;
  proto_tree *tlv_tree, *tlv_subtree;
  uint32_t tlv_type, tlv_subtype;
  int tlv_length, end = pos + length, i, attr_end;

  uint32_t value;
  const char * label;
  asn1_ctx_t asn1_ctx;

  static int *const bpkmattr_crypto_suite[] = {
    &hf_docsis_bpkmattr_crypto_suite_encr,
    &hf_docsis_bpkmattr_crypto_suite_auth,
    NULL
  };

  increment_dissection_depth(pinfo);
  while (pos + 2 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_ntohs(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_bpkmattr_tlv, tvb, pos, tlv_length + 3, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, bpkmattr_tlv_vals, "Unknown TLV: %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_bpkmattr_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_tlv_length, tvb, pos + 1, 2, ENC_BIG_ENDIAN);
    pos += 3;

    if (tlv_length > 1487)
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "TLV length too big: %i", tlv_length);

    switch (tlv_type)
    {
    case BPKM_SERIAL_NUM:
      proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_serial_num, tvb, pos, tlv_length, ENC_ASCII);
      if (tlv_length > 255)
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "TLV length too big: %i", tlv_length);
      break;
    case BPKM_MANUFACTURER_ID:
      if (tlv_length == 3) {
        tlv_subitem = proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_bpkmattr_manf_id, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        label = uint_get_manuf_name_if_known(value);
        proto_item_append_text(tlv_subitem, " (%s)", label ? label : "unknown OUI");
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_MAC_ADDR:
      if (tlv_length == 6)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_mac_addr, tvb, pos, tlv_length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_RSA_PUB_KEY:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_pkcs1_RSAPublicKey(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_rsa_pub_key);
      break;
    case BPKM_CM_ID:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_cm_id, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_cmid);
      dissect_attrs(tvb, pinfo, tlv_item, tlv_subtree, pos, tlv_length);
      if (tlv_length < 126)
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "TLV length too small: %i", tlv_length);
      break;
    case BPKM_DISPLAY_STR:
      proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_display_str, tvb, pos, tlv_length, ENC_ASCII);
      if (tlv_length > 128)
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "TLV length too big: %i", tlv_length);
      break;
    case BPKM_AUTH_KEY:
      if (tlv_length == 96 || tlv_length == 128 || tlv_length == 256)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_auth_key, tvb, pos, tlv_length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_TEK:
      if (tlv_length == 8 || tlv_length == 16 || tlv_length == 32)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_tek, tvb, pos, tlv_length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_KEY_LIFETIME:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_key_life, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_KEY_SEQ_NUM:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_key_seq, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_HMAC_DIGEST:
      if (tlv_length == 20)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_hmac_digest, tvb, pos, tlv_length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_SAID:
      if (tlv_length == 2)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_said, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_TEK_PARAM:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_tek_params, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_tekp);
      dissect_attrs(tvb, pinfo, tlv_item, tlv_subtree, pos, tlv_length);
      break;
    case BPKM_OBSOLETED:
      break;
    case BPKM_CBC_IV:
      if (tlv_length == 8 || tlv_length == 16)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_cbc_iv, tvb, pos, tlv_length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_ERROR_CODE:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_error_code, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_CA_CERT:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_x509af_Certificate(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_ca_cert);
      break;
    case BPKM_CM_CERT:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_x509af_Certificate(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_cm_cert);
      break;
    case BPKM_SEC_CAPABILITIES:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_security_cap, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_scap);
      dissect_attrs(tvb, pinfo, tlv_item, tlv_subtree, pos, tlv_length);
      break;
    case BPKM_CRYPTO_SUITE:
      if (tlv_length == 2)
        proto_tree_add_bitmask(tlv_tree, tvb, pos, hf_docsis_bpkmattr_crypto_suite,
                               ett_docsis_bpkmattr_crypto_suite, bpkmattr_crypto_suite, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_CRYPTO_SUITE_LIST:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_crypto_suite_list, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_crypto_suite_list);
      for (i = 0; i < tlv_length - 1; i += 2)
        proto_tree_add_bitmask(tlv_subtree, tvb, pos + i, hf_docsis_bpkmattr_crypto_suite,
                               ett_docsis_bpkmattr_crypto_suite, bpkmattr_crypto_suite, ENC_BIG_ENDIAN);
      if (i < tlv_length)
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_BPI_VERSION:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_bpi_version, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_SA_DESCRIPTOR:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_sa_descr, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_sadsc);
      dissect_attrs(tvb, pinfo, tlv_item, tlv_subtree, pos, tlv_length);
      break;
    case BPKM_SA_TYPE:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_sa_type, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_SA_QUERY:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_sa_query, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_saqry);
      dissect_attrs(tvb, pinfo, tlv_item, tlv_subtree, pos, tlv_length);
      break;
    case BPKM_SA_QUERY_TYPE:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_sa_query_type, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_IP_ADDRESS:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_ip_address, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_DNLD_PARAMS:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_download_param, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_dnld);
      dissect_attrs(tvb, pinfo, tlv_item, tlv_subtree, pos, tlv_length);
      break;
    case BPKM_CVC_ROOT_CA_CERT:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_x509af_Certificate(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_cvc_root_ca_cert);
      break;
    case BPKM_CVC_CA_CERT:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_x509af_Certificate(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_cvc_ca_cert);
      break;
    case BPKM_DEV_CA_CERT:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_x509af_Certificate(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_dev_ca_cert);
      break;
    case BPKM_ROOT_CA_CERT:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_x509af_Certificate(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_root_ca_cert);
      break;
    case BPKM_CM_NONCE:
      if (tlv_length == 8)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_cm_nonce, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_MSG_SIGNATURE:
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      dissect_cms_SignedData(false, tvb, pos, &asn1_ctx, tlv_tree, hf_docsis_bpkmattr_msg_signature);
      break;
    case BPKM_KEY_EXCHANGE_SHARE:
      if (tlv_length > 2) {
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_key_exchange_share_field_id, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_key_exchange_share_key_share, tvb, pos + 2, tlv_length - 2, ENC_NA);
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_ALLOWED_BPI_VERSIONS:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_allowed_bpi_versions, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_allowed_bpi_versions);
      for (i = 0; i < tlv_length; ++i)
        proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_allowed_bpi_version, tvb, pos + i, 1, ENC_BIG_ENDIAN);
      break;
    case BPKM_OCSP_RSP:
      tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_ocsp_responses, tvb, pos, tlv_length, ENC_NA);
      tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_ocsp_responses);
      asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
      i = pos;
      attr_end = pos + tlv_length;
      while (i < attr_end)
        i = dissect_ocsp_OCSPResponse(false, tvb, i, &asn1_ctx, tlv_subtree, hf_docsis_bpkmattr_ocsp_response);
      break;
    case BPKM_CMTS_DESIGNATION:
      if (tlv_length) {
        tlv_subitem = proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_cmts_designation, tvb, pos, tlv_length, ENC_NA);
        tlv_subtree = proto_item_add_subtree(tlv_subitem, ett_docsis_bpkmattr_cmts_designation);
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_bpkmattr_cmts_designation_data_type,
                                     tvb, pos, 1, ENC_BIG_ENDIAN, &tlv_subtype);
        switch (tlv_subtype)
        {
        case BPKMATTR_CMTS_DESIGNATION_CERTIFICATE_FINGERPRINT:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_certificate_fingerprint,
                              tvb, pos + 1, tlv_length - 1, ENC_NA);
          break;
        case BPKMATTR_CMTS_DESIGNATION_COMMON_NAME:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_common_name,
                              tvb, pos + 1, tlv_length - 1, ENC_ASCII);
          break;
        case BPKMATTR_CMTS_DESIGNATION_ORG_UNIT:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_org_unit,
                              tvb, pos + 1, tlv_length - 1, ENC_ASCII);
          break;
        case BPKMATTR_CMTS_DESIGNATION_ORG_NAME:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_org_name,
                              tvb, pos + 1, tlv_length - 1, ENC_ASCII);
          break;
        case BPKMATTR_CMTS_DESIGNATION_SERIAL_NUMBER:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_serial_number,
                              tvb, pos + 1, tlv_length - 1, ENC_ASCII);
          break;
        case BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_FINGERPRINT:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_issuing_ca_fingerprint,
                              tvb, pos + 1, tlv_length - 1, ENC_NA);
          break;
        case BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_COMMON_NAME:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_issuing_ca_common_name,
                              tvb, pos + 1, tlv_length - 1, ENC_ASCII);
          break;
        case BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_ORG_UNIT:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_issuing_ca_org_unit,
                              tvb, pos + 1, tlv_length - 1, ENC_ASCII);
          break;
        case BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_ORG_NAME:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_issuing_ca_org_name,
                              tvb, pos + 1, tlv_length - 1, ENC_ASCII);
          break;
        case BPKMATTR_CMTS_DESIGNATION_ISSUING_CA_SERIAL_NUMBER:
          proto_tree_add_item(tlv_subtree, hf_docsis_bpkmattr_cmts_designation_issuing_ca_serial_number,
                              tvb, pos, tlv_length - 1, ENC_ASCII);
          break;
        }
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_CM_STATUS_CODE:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_cm_status_code, tvb, pos, tlv_length, ENC_NA);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_DETECTED_ERRORS:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_detected_errors, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case BPKM_VENDOR_DEFINED:
      proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_vendor_def, tvb, pos, tlv_length, ENC_NA);
      break;
    default:
      proto_tree_add_item(tlv_tree, hf_docsis_bpkmattr_vendor_def, tvb, pos, tlv_length, ENC_NA);
      break;
    }

    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
  decrement_dissection_depth(pinfo);
}

static int
dissect_bpkmreq(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *bpkmreq_item, *attr_item;
  proto_tree *bpkmreq_tree, *attr_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t code, id, length;

  bpkmreq_item = proto_tree_add_item(tree, proto_docsis_bpkmreq, tvb, 0, -1, ENC_NA);
  bpkmreq_tree = proto_item_add_subtree(bpkmreq_item, ett_docsis_bpkmreq);
  proto_tree_add_item_ret_uint(bpkmreq_tree, hf_docsis_bpkm_code, tvb, 0, 1, ENC_BIG_ENDIAN, &code);
  proto_tree_add_item_ret_uint(bpkmreq_tree, hf_docsis_bpkm_ident, tvb, 1, 1, ENC_BIG_ENDIAN, &id);
  proto_tree_add_item_ret_uint(bpkmreq_tree, hf_docsis_bpkm_length, tvb, 2, 2, ENC_BIG_ENDIAN, &length);

  col_add_fstr(pinfo->cinfo, COL_INFO, "BPKM Request (BPKM-REQ): %s, ID %u",
               val_to_str(code, code_field_vals, "Unknown Code (%u)"), id);

  id += code << 8;
  tlv_tvb = dissect_multipart(tvb, pinfo, bpkmreq_tree, data, MGT_BPKM_REQ, id, 4);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb)) {
    attr_item = proto_tree_add_item(bpkmreq_tree, hf_docsis_bpkmattr, tlv_tvb, 0, length, ENC_NA);
    attr_tree = proto_item_add_subtree(attr_item, ett_docsis_bpkmattr);
    dissect_attrs(tlv_tvb, pinfo, attr_item, attr_tree, 0, length);
    if (length != tvb_reported_length(tlv_tvb))
      expert_add_info_format(pinfo, bpkmreq_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
  }
  return tvb_captured_length(tvb);
}

static int
dissect_bpkmrsp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *bpkmrsp_item, *attr_item;
  proto_tree *bpkmrsp_tree, *attr_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t code, id, length;

  bpkmrsp_item = proto_tree_add_item(tree, proto_docsis_bpkmrsp, tvb, 0, -1, ENC_NA);
  bpkmrsp_tree = proto_item_add_subtree(bpkmrsp_item, ett_docsis_bpkmrsp);
  proto_tree_add_item_ret_uint(bpkmrsp_tree, hf_docsis_bpkm_code, tvb, 0, 1, ENC_BIG_ENDIAN, &code);
  proto_tree_add_item_ret_uint(bpkmrsp_tree, hf_docsis_bpkm_ident, tvb, 1, 1, ENC_BIG_ENDIAN, &id);
  proto_tree_add_item_ret_uint(bpkmrsp_tree, hf_docsis_bpkm_length, tvb, 2, 2, ENC_BIG_ENDIAN, &length);

  col_add_fstr(pinfo->cinfo, COL_INFO, "BPKM Response (BPKM-RSP): %s, ID %u",
               val_to_str(code, code_field_vals, "Unknown Code (%u)"), id);

  id += code << 8;
  tlv_tvb = dissect_multipart(tvb, pinfo, bpkmrsp_tree, data, MGT_BPKM_RSP, id, 4);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb)) {
    attr_item = proto_tree_add_item(bpkmrsp_tree, hf_docsis_bpkmattr, tlv_tvb, 0, length, ENC_NA);
    attr_tree = proto_item_add_subtree(attr_item, ett_docsis_bpkmattr);
    dissect_attrs(tlv_tvb, pinfo, attr_item, attr_tree, 0, length);
    if (length != tvb_reported_length(tlv_tvb))
      expert_add_info_format(pinfo, bpkmrsp_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
  }
  return tvb_captured_length(tvb);
}

static int
dissect_regack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regack_tree;
  uint32_t sid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_regack, tvb, 0, -1, ENC_NA);
  regack_tree = proto_item_add_subtree (it, ett_docsis_regack);

  proto_tree_add_item_ret_uint (regack_tree, hf_docsis_regack_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item_ret_uint (regack_tree, hf_docsis_regack_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Registration Acknowledge SID = %u (%s)", sid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLVs */
  if(tvb_reported_length_remaining(tvb, 3) > 0 )
  {
    next_tvb = tvb_new_subset_remaining (tvb, 3);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, regack_tree);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_dsareq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsareq_tree;
  uint32_t transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_dsareq, tvb, 0, -1, ENC_NA);
  dsareq_tree = proto_item_add_subtree (it, ett_docsis_dsareq);

  proto_tree_add_item_ret_uint (dsareq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Addition Request Tran-id = %u ", transid);

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsareq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsarsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsarsp_tree;
  uint32_t transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dsarsp, tvb, 0, -1, ENC_NA);
  dsarsp_tree = proto_item_add_subtree (it, ett_docsis_dsarsp);
  proto_tree_add_item_ret_uint (dsarsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dsarsp_tree, hf_docsis_dsarsp_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Add Response ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsarsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsaack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsaack_tree;
  uint32_t transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dsaack, tvb, 0, -1, ENC_NA);
  dsaack_tree = proto_item_add_subtree (it, ett_docsis_dsaack);
  proto_tree_add_item_ret_uint (dsaack_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dsaack_tree, hf_docsis_dsaack_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Add Acknowledge: Transaction ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsaack_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dscreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dscreq_tree;
  uint32_t transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dscreq, tvb, 0, -1, ENC_NA);
  dscreq_tree = proto_item_add_subtree (it, ett_docsis_dscreq);

  proto_tree_add_item_ret_uint (dscreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Change Request Tran-id = %u ", transid);

  /* Call dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dscrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dscrsp_tree;
  uint32_t transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_dscrsp, tvb, 0, -1, ENC_NA);
  dscrsp_tree = proto_item_add_subtree (it, ett_docsis_dscrsp);
  proto_tree_add_item_ret_uint (dscrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dscrsp_tree, hf_docsis_dscrsp_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Change Response: Transaction ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dscack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dscack_tree;
  uint32_t transid, response;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_dscack, tvb, 0, -1, ENC_NA);
  dscack_tree = proto_item_add_subtree (it, ett_docsis_dscack);

  proto_tree_add_item_ret_uint (dscack_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dscack_tree, hf_docsis_dscack_response, tvb, 2, 1, ENC_BIG_ENDIAN, &response);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Change Acknowledge: Transaction ID = %u (%s)", transid,
                val_to_str_ext (response, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dscack_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsdreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsdreq_tree;
  uint32_t transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_dsdreq, tvb, 0, -1, ENC_NA);
  dsdreq_tree = proto_item_add_subtree (it, ett_docsis_dsdreq);

  proto_tree_add_item_ret_uint (dsdreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Delete Request Tran-id = %u ", transid);

  proto_tree_add_item (dsdreq_tree, hf_docsis_dsdreq_rsvd, tvb, 2, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dsdreq_tree, hf_docsis_dsdreq_sfid, tvb, 4, 4, ENC_BIG_ENDIAN);

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 8);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dsdreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dsdrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dsdrsp_tree;
  uint32_t tranid, confcode;

  it = proto_tree_add_item(tree, proto_docsis_dsdrsp, tvb, 0, -1, ENC_NA);
  dsdrsp_tree = proto_item_add_subtree (it, ett_docsis_dsdrsp);
  proto_tree_add_item_ret_uint (dsdrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &tranid);
  proto_tree_add_item_ret_uint (dsdrsp_tree, hf_docsis_dsdrsp_confcode, tvb, 2, 1, ENC_BIG_ENDIAN, &confcode);
  proto_tree_add_item (dsdrsp_tree, hf_docsis_dsdrsp_rsvd, tvb, 3, 1, ENC_BIG_ENDIAN);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Service Delete Response: Transaction ID = %u (%s)",
                tranid, val_to_str_ext (confcode, &docsis_conf_code_ext, "%d"));

  return tvb_captured_length(tvb);
}

static void
dissect_dccreq_ds_params (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcc_tree;
  proto_item *dcc_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcc_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dccreq_ds_params, &dcc_item,
                                            val_to_str(type, ds_param_subtlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcc_tree, hf_docsis_dcc_ds_params_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcc_tree, hf_docsis_dcc_ds_params_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcc_item, length + 2);

    switch (type)
    {
    case DCCREQ_DS_FREQ:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_freq, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_MOD_TYPE:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_mod_type, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_SYM_RATE:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_sym_rate, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_INTLV_DEPTH:
      if (length == 2)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_intlv_depth_i, tvb, pos, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_intlv_depth_j, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_CHAN_ID:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_chan_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_SYNC_SUB:
      if (length == 1)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_sync_sub, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_OFDM_BLOCK_FREQ:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_ds_ofdm_block_freq, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_dccreq_sf_sub (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcc_tree;
  proto_item *dcc_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcc_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dccreq_sf_sub, &dcc_item,
                                            val_to_str(type, sf_sub_subtlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcc_tree, hf_docsis_dcc_sf_sub_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcc_tree, hf_docsis_dcc_sf_sub_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcc_item, length + 2);

    switch (type)
    {
    case DCCREQ_SF_SFID:
      if (length == 8)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sfid_cur, tvb, pos, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sfid_new, tvb, pos + 4, 4, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_SF_SID:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sid_cur, tvb, pos, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_sid_new, tvb, pos + 2, 2, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_SF_UNSOL_GRANT_TREF:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccreq_sf_unsol_grant_tref, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static int
dissect_dccreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  uint16_t pos;
  uint8_t type;
  uint32_t length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-REQ Message");

  dcc_item = proto_tree_add_item (tree, proto_docsis_dccreq, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccreq);

  proto_tree_add_item (dcc_tree, hf_docsis_dccreq_tran_id, tvb, 0, 2, ENC_BIG_ENDIAN);

  pos = 2;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccreq_tlv, &tlv_item,
                                            val_to_str(type, dcc_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dccreq_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dccreq_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCREQ_UP_CHAN_ID:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_up_chan_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_DS_PARAMS:
      dissect_dccreq_ds_params (tvb, pinfo, tlv_tree, pos, length);
      break;
    case DCCREQ_INIT_TECH:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_init_tech, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_UCD_SUB:
      proto_tree_add_item (tlv_tree, hf_docsis_dccreq_ucd_sub, tvb, pos, length, ENC_NA);
      break;
    case DCCREQ_SAID_SUB:
      if (length == 4)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_said_sub_cur, tvb, pos, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_said_sub_new, tvb, pos + 2, 2, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_SF_SUB:
      dissect_dccreq_sf_sub (tvb, pinfo, tlv_tree, pos, length );
      break;
    case DCCREQ_CMTS_MAC_ADDR:
      if (length == 6)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_cmts_mac_addr, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCREQ_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccreq_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }       /* switch(type) */
    pos += length;
  }         /* (tvb_reported_length_remaining(tvb, pos) > 0) */
  return tvb_captured_length(tvb);
}

static void
dissect_dccrsp_cm_jump_time (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcc_tree;
  proto_item *dcc_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcc_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dccrsp_cm_jump_time, &dcc_item,
                                            val_to_str(type, cm_jump_subtlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcc_tree, hf_docsis_dcc_cm_jump_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcc_tree, hf_docsis_dcc_cm_jump_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcc_item, length + 2);

    switch (type)
    {
    case DCCRSP_CM_JUMP_TIME_LENGTH:
      if (length == 4)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_cm_jump_time_length, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCRSP_CM_JUMP_TIME_START:
      if (length == 8)
      {
        proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_cm_jump_time_start, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static int
dissect_dccrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  uint16_t pos;
  uint8_t type;
  uint32_t length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-RSP Message");

  dcc_item = proto_tree_add_item (tree, proto_docsis_dccrsp, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccrsp);
  proto_tree_add_item (dcc_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dcc_tree, hf_docsis_dccrsp_conf_code, tvb, 2, 1, ENC_BIG_ENDIAN);

  pos = 3;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccrsp_tlv, &tlv_item,
                                            val_to_str(type, dccrsp_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dccrsp_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dccrsp_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCRSP_CM_JUMP_TIME:
      dissect_dccrsp_cm_jump_time (tvb, pinfo, tlv_tree, pos, length );
      break;
    case DCCRSP_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccrsp_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCRSP_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccrsp_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }      /* switch(type) */

    pos += length;
  }       /* while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

static int
dissect_dccack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  uint16_t pos;
  uint8_t type;
  uint32_t length;
  proto_tree *dcc_tree, *tlv_tree;
  proto_item *dcc_item, *tlv_item, *tlv_len_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCC-ACK Message");

  dcc_item = proto_tree_add_item(tree, proto_docsis_dccack, tvb, 0, -1, ENC_NA);
  dcc_tree = proto_item_add_subtree (dcc_item, ett_docsis_dccack);
  proto_tree_add_item (dcc_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN);

  pos = 2;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcc_tree, tvb, pos, -1,
                                            ett_docsis_dccack_tlv, &tlv_item,
                                            val_to_str(type, dccack_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dccack_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dccack_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCCACK_KEY_SEQ_NUM:
      if (length == 1)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccack_key_seq_num, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCCACK_HMAC_DIGEST:
      if (length == 20)
      {
        proto_tree_add_item (tlv_tree, hf_docsis_dccack_hmac_digest, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }      /* switch(type) */

    pos += length;
  }        /*   while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

static int
dissect_type29ucd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_type29ucd, MGT_TYPE29UCD);
}

static int
dissect_intrngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *intrngreq_item;
  proto_tree *intrngreq_tree;
  uint32_t sid;

  intrngreq_item = proto_tree_add_item(tree, proto_docsis_intrngreq, tvb, 0, -1, ENC_NA);
  intrngreq_tree = proto_item_add_subtree (intrngreq_item, ett_docsis_intrngreq);

  proto_tree_add_item_ret_uint (intrngreq_tree, hf_docsis_intrngreq_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  col_add_fstr (pinfo->cinfo, COL_INFO, "Initial Ranging Request: SID = %u",sid);

  proto_tree_add_item (intrngreq_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (intrngreq_tree, hf_docsis_mgt_upstream_chid, tvb, 3, 1, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static void
dissect_dcd_dsg_cfg (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_cfg, &dcd_item,
                                            val_to_str(type, dcd_cfg_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_cfg_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_cfg_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CFG_CHAN_LST:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_chan, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG1:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg1, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG2:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg2, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG3:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg3, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_TDSG4:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_tdsg4, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFG_VENDOR_SPEC:
      proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfg_vendor_spec, tvb, pos, length, ENC_NA);
      break;

    }

    pos += length;
  }
}

static void
dissect_dcd_down_classifier_ip (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_cfr_ip, &dcd_item,
                                            val_to_str(type, dcd_cfr_ip_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_cfr_ip_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_cfr_ip_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CFR_IP_SOURCE_ADDR:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_source_addr, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_SOURCE_MASK:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_source_mask, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_DEST_ADDR:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_dest_addr, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_DEST_MASK:
      if (length == 4)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_ip_dest_mask, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_SRCPORT_START:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_srcport_start, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_SRCPORT_END:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_srcport_end, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_DSTPORT_START:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_dstport_start, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_TCPUDP_DSTPORT_END:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_tcpudp_dstport_end, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_dcd_clid (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_clid, &dcd_item,
                                            val_to_str(type, dcd_clid_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_clid_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_clid_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CLID_BCAST_ID:
      if (length == 2)
      {
        proto_tree_add_item(dcd_tree, hf_docsis_dcd_clid_bcast_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CLID_KNOWN_MAC_ADDR:
      if (length == 6)
      {
       proto_tree_add_item (dcd_tree, hf_docsis_dcd_clid_known_mac_addr, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CLID_CA_SYS_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_clid_ca_sys_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CLID_APP_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_clid_app_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_dcd_dsg_rule (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_rule, &dcd_item,
                                            val_to_str(type, dcd_dsg_rule_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_dsg_rule_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_dsg_rule_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_RULE_ID:
      if (length == 1)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_PRI:
      if (length == 1)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_pri, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_UCID_RNG:
      proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_ucid_list, tvb, pos, length, ENC_NA);
      break;
    case DCD_RULE_CLIENT_ID:
      dissect_dcd_clid (tvb, pinfo, dcd_tree, pos, length );
      break;
    case DCD_RULE_TUNL_ADDR:
      if (length == 6)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_tunl_addr, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_CFR_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_cfr_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_RULE_VENDOR_SPEC:
      proto_tree_add_item (dcd_tree, hf_docsis_dcd_rule_vendor_spec, tvb, pos, length, ENC_NA);
      break;

    }

    pos += length;
  }
}

static void
dissect_dcd_down_classifier (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *dcd_tree;
  proto_tree *dcd_item, *tlv_len_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    dcd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_dcd_cfr, &dcd_item,
                                            val_to_str(type, dcd_down_classifier_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (dcd_tree, hf_docsis_dcd_down_classifier_subtype, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (dcd_tree, hf_docsis_dcd_down_classifier_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(dcd_item, length + 2);

    switch (type)
    {
    case DCD_CFR_ID:
      if (length == 2)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_RULE_PRI:
      if (length == 1)
      {
        proto_tree_add_item (dcd_tree, hf_docsis_dcd_cfr_rule_pri, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DCD_CFR_IP_CLASSIFIER:
      dissect_dcd_down_classifier_ip (tvb , pinfo , dcd_tree , pos , length );
      break;
    }

    pos += length;
  }
}

static int
dissect_dcd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  uint16_t pos;
  uint8_t type;
  uint32_t length;
  proto_tree *dcd_tree, *tlv_tree;
  proto_item *dcd_item, *tlv_item;

  col_set_str(pinfo->cinfo, COL_INFO, "DCD Message: ");

  dcd_item = proto_tree_add_item(tree, proto_docsis_dcd, tvb, 0, -1, ENC_NA);
  dcd_tree = proto_item_add_subtree (dcd_item, ett_docsis_dcd);
  proto_tree_add_item (dcd_tree, hf_docsis_dcd_config_ch_cnt, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dcd_tree, hf_docsis_dcd_num_of_frag, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dcd_tree, hf_docsis_dcd_frag_sequence_num, tvb, 2, 1, ENC_BIG_ENDIAN);

  pos = 3;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlv_tree = proto_tree_add_subtree(dcd_tree, tvb, pos, -1,
                                            ett_docsis_dcd_tlv, &tlv_item,
                                            val_to_str(type, dcd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlv_tree, hf_docsis_dcd_type, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (tlv_tree, hf_docsis_dcd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DCD_DOWN_CLASSIFIER:
      dissect_dcd_down_classifier (tvb, pinfo, tlv_tree, pos, length);
      break;
    case DCD_DSG_RULE:
      dissect_dcd_dsg_rule (tvb, pinfo, tlv_tree, pos, length);
      break;
    case DCD_DSG_CONFIG:
      dissect_dcd_dsg_cfg (tvb, pinfo, tlv_tree, pos, length);
      break;
    }     /* switch(type) */

     pos += length;
  }       /* while (tvb_reported_length_remaining(tvb, pos) > 0) */

  return tvb_captured_length(tvb);
}

static void
dissect_mdd_ds_active_channel_list(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;
  static int * const order_annex[] = {
    &hf_docsis_mdd_downstream_active_channel_list_modulation_order,
    &hf_docsis_mdd_downstream_active_channel_list_annex,
    NULL
  };
  static int * const cm_status_event[] = {
    &hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery,
    NULL
  };
  static int * const ofdm_plc_parameters[] = {
    &hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window,
    &hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix,
    &hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing,
    NULL
  };

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ds_active_channel_list, &mdd_item,
                                            val_to_str(type, mdd_ds_active_channel_list_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ds_active_channel_list_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ds_active_channel_list_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CHANNEL_ID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_channel_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_FREQUENCY:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_frequency, tvb, pos, 4, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_MODULATION_ORDER_ANNEX:
      proto_tree_add_bitmask_list(mdd_tree, tvb, pos, 1, order_annex, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_PRIMARY_CAPABLE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_primary_capable, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_bitmask, ett_sub_tlv, cm_status_event, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_MAP_UCD_TRANSPORT_INDICATOR:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_OFDM_PLC_PARAMETERS:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_ofdm_plc_parameters, ett_sub_tlv, ofdm_plc_parameters, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_FDX_SUB_BAND_ID:
      proto_tree_add_item(mdd_tree, hf_docsis_mdd_downstream_active_channel_list_fdx_sub_band_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST_FDX_DS:
      proto_tree_add_item(mdd_tree, hf_docsis_mdd_downstream_active_channel_list_fdx_ds, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_ds_service_group(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t i, length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ds_service_group, &mdd_item,
                                            val_to_str(type, mdd_ds_service_group_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ds_service_group_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ds_service_group_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_MD_DS_SG_IDENTIFIER:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier, tvb, pos, 1, ENC_BIG_ENDIAN);
     break;
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP_CHANNEL_IDS:
      for (i = 0; i < length; i++) {
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_mac_domain_downstream_service_group_channel_id, tvb, pos + i , 1, ENC_BIG_ENDIAN);
      }
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_channel_profile_reporting_control(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_channel_profile_reporting_control, &mdd_item,
                                            val_to_str(type, mdd_channel_profile_reporting_control_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_channel_profile_reporting_control_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_channel_profile_reporting_control_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case RCP_CENTER_FREQUENCY_SPACING:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_rcp_center_frequency_spacing, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case VERBOSE_RCP_REPORTING:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_verbose_rcp_reporting, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case FRAGMENTED_RCP_TRANSMISSION:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_fragmented_rcp_transmission, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_ip_init_param(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_ip_init_param, &mdd_item,
                                            val_to_str(type, mdd_ip_init_param_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_ip_init_param_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_ip_init_param_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case IP_PROVISIONING_MODE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_ip_provisioning_mode, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case PRE_REGISTRATION_DSID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_pre_registration_dsid, tvb, pos, 3, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_upstream_active_channel_list_dschids_maps_ucds(tvbuff_t * tvb, proto_tree * tree, unsigned start, uint16_t len)
{
  uint16_t i;
  proto_item *it;
  proto_tree *dschid_tree;

  it = proto_tree_add_item (tree, hf_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds, tvb, start, len, ENC_NA);
  dschid_tree = proto_item_add_subtree (it, ett_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds_dschids);

  for(i = 0; i< len; ++i)
  {
    proto_tree_add_item (dschid_tree, hf_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds_dschid, tvb, start + i, 1, ENC_BIG_ENDIAN);
  }
}

static void
dissect_mdd_upstream_active_channel_list(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;
  static int * const cm_status_event[] = {
    &hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded,
    &hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded,
    NULL
  };

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_up_active_channel_list, &mdd_item,
                                            val_to_str(type, mdd_up_active_channel_list_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_up_active_channel_list_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_up_active_channel_list_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_ID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST_CM_STATUS_EVENT_ENABLE_BITMASK:
      proto_tree_add_bitmask(mdd_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_bitmask, ett_sub_tlv, cm_status_event, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST_UPSTREAM_CHANNEL_PRIORITY:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_upstream_active_channel_list_upstream_channel_priority, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST_DSCHIDS_MAPS_UCDS:
      dissect_mdd_upstream_active_channel_list_dschids_maps_ucds(tvb, mdd_tree, pos, length);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST_FDX_UPSTREAM_CHANNEL:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_upstream_active_channel_list_fdx_upstream_channel, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST_FDX_SUBBAND_ID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_upstream_active_channel_list_fdx_subband_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_cm_status_event_control(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length, timer;
  proto_tree *mdd_tree;
  proto_item *mdd_item, *text_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_cm_status_event_control, &mdd_item,
                                            val_to_str(type, mdd_cm_status_event_control_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_cm_status_event_control_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_cm_status_event_control_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case EVENT_TYPE_CODE:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_event_type, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case MAXIMUM_EVENT_HOLDOFF_TIMER:
      text_item = proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_maximum_event_holdoff_timer, tvb, pos, 2, ENC_BIG_ENDIAN, &timer);
      proto_item_append_text(text_item, " (%d ms)", timer * 20);
      break;
    case MAXIMUM_NUMBER_OF_REPORTS_PER_EVENT:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_maximum_number_of_reports_per_event, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_dsg_da_to_dsid(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_mdd_dsg_da_to_dsid, &mdd_item,
                                            val_to_str(type, mdd_cm_dsg_da_to_dsid_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_subtype, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    switch(type)
    {
    case DSG_DA_TO_DSID_ASSOCIATION_DA:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_association_da, tvb, pos, 6, ENC_NA);
      break;
    case DSG_DA_TO_DSID_ASSOCIATION_DSID:
      proto_tree_add_item (mdd_tree, hf_docsis_mdd_dsg_da_to_dsid_association_dsid, tvb, pos, 3, ENC_BIG_ENDIAN);
      break;
    }

    pos += length;
  }
}

static void
dissect_mdd_docsis_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;
  uint32_t tlv_value;

  int major = -1, minor = -1;
  int major_pos = 0, minor_pos = 0;
  uint8_t ext_spectrum_mode = 0;

  static int *const mdd_cmts_docsis_version_ext_spectrum_mode[] = {
    &hf_docsis_mdd_docsis_version_ext_spectrum_mode_fdd,
    &hf_docsis_mdd_docsis_version_ext_spectrum_mode_fdx,
    NULL
  };

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_mdd_docsis_version_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, mdd_docsis_version_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_mdd_docsis_version);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_docsis_version_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_docsis_version_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case CMTS_DOCSIS_VERSION_MAJOR_PRE_40:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_mdd_docsis_version_major_pre_40,
                                     tvb, pos, tlv_length, ENC_BIG_ENDIAN, &tlv_value);
        if (major < 0) {
          major = tlv_value;
          major_pos = pos;
        }
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CMTS_DOCSIS_VERSION_MINOR_PRE_40:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_mdd_docsis_version_minor_pre_40,
                                     tvb, pos, tlv_length, ENC_BIG_ENDIAN, &tlv_value);
        if (minor < 0) {
          minor = tlv_value;
          minor_pos = pos;
        }
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CMTS_DOCSIS_VERSION_MAJOR:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_mdd_docsis_version_major,
                                     tvb, pos, tlv_length, ENC_BIG_ENDIAN, &tlv_value);
        major = tlv_value;
        major_pos = pos;
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CMTS_DOCSIS_VERSION_MINOR:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_mdd_docsis_version_minor,
                                     tvb, pos, tlv_length, ENC_BIG_ENDIAN, &tlv_value);
        minor = tlv_value;
        minor_pos = pos;
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE:
      if (tlv_length == 1) {
        ext_spectrum_mode = tvb_get_uint8(tvb, pos);
        proto_tree_add_bitmask_value(tlv_tree, tvb, pos, hf_docsis_mdd_docsis_version_ext_spectrum_mode,
                                     ett_docsis_mdd_docsis_version_tlv,
                                     mdd_cmts_docsis_version_ext_spectrum_mode, ext_spectrum_mode);
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (major > -1)
    proto_item_set_hidden(proto_tree_add_item(tree, hf_docsis_mdd_cmts_major_docsis_version, tvb, major_pos, 1, ENC_BIG_ENDIAN));
  if (minor > -1)
    proto_item_set_hidden(proto_tree_add_item(tree, hf_docsis_mdd_cmts_minor_docsis_version, tvb, minor_pos, 1, ENC_BIG_ENDIAN));
  if (major > -1 && minor > -1)
    proto_item_append_text(item, ": DOCSIS %d.%d%s%s", major, minor,
                           (ext_spectrum_mode & CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE_FDD) ? " + FDD" : "",
                           (ext_spectrum_mode & CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE_FDX) ? " + FDX" : "");
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_mdd_diplexer_band_edge(tvbuff_t * tvb, packet_info* pinfo _U_, proto_tree * tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  uint16_t override_mhz;
  proto_tree *mdd_tree;
  proto_item *mdd_item;
  int pos;

  pos = start;
  while ( pos < ( start + len) )
  {
    type = tvb_get_uint8 (tvb, pos);
    mdd_tree = proto_tree_add_subtree(tree, tvb, pos, 1,
                                            ett_docsis_mdd_diplexer_band_edge, &mdd_item,
                                            val_to_str(type, mdd_diplexer_band_edge_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (mdd_tree, hf_docsis_mdd_diplexer_band_edge, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (mdd_tree, hf_docsis_mdd_diplexer_band_edge_length, tvb, pos, 1, ENC_BIG_ENDIAN, &length);
    pos++;
    proto_item_set_len(mdd_item, length + 2);

    if (length == 1 || length == 2)
    {
      switch(type)
      {
      case DIPLEXER_US_UPPER_BAND_EDGE:
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_diplexer_us_upper_band_edge, tvb, pos, length, ENC_BIG_ENDIAN);
        break;
      case DIPLEXER_DS_LOWER_BAND_EDGE:
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_diplexer_ds_lower_band_edge, tvb, pos, length, ENC_BIG_ENDIAN);
        break;
      case DIPLEXER_DS_UPPER_BAND_EDGE:
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_diplexer_ds_upper_band_edge, tvb, pos, length, ENC_BIG_ENDIAN);
        break;
      case DIPLEXER_US_UPPER_BAND_EDGE_OVERRIDE:
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_diplexer_us_upper_band_edge_override, tvb, pos, length, ENC_BIG_ENDIAN);
        override_mhz = tvb_get_ntohs (tvb, pos);
        if (override_mhz != 204 && override_mhz != 300 && override_mhz != 396 && override_mhz != 492 && override_mhz != 684)
          {
            expert_add_info_format(pinfo, mdd_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown Diplexer Upstream Upper Band Edge Override value: %u", override_mhz);
          }
        break;
      case DIPLEXER_DS_LOWER_BAND_EDGE_OVERRIDE:
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_diplexer_ds_lower_band_edge_override, tvb, pos, length, ENC_BIG_ENDIAN);
        override_mhz = tvb_get_ntohs (tvb, pos);
        if (override_mhz != 108 && override_mhz != 258 && override_mhz != 372 && override_mhz != 492 && override_mhz != 606 && override_mhz != 834)
          {
            expert_add_info_format(pinfo, mdd_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown Diplexer Downstream Lower Band Edge Override value: %u", override_mhz);
          }
        break;
      case DIPLEXER_DS_UPPER_BAND_EDGE_OVERRIDE:
        proto_tree_add_item (mdd_tree, hf_docsis_mdd_diplexer_ds_upper_band_edge_override, tvb, pos, length, ENC_BIG_ENDIAN);
        override_mhz = tvb_get_ntohs (tvb, pos);
        if (override_mhz != 1002 && override_mhz != 1218 && override_mhz != 1794)
          {
            expert_add_info_format(pinfo, mdd_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown Diplexer Downstream Upper Band Edge Override value: %u", override_mhz);
          }
        break;
      default:
        expert_add_info_format(pinfo, mdd_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown Diplexer Band Edge TLV type: %u", type);
        break;
      }
    } else
    {
      expert_add_info_format(pinfo, mdd_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      break;
    }
    pos += length;
  }
}

static void
dissect_mdd_advanced_band_plan(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_mdd_abp_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, mdd_abp_vals, "Unknown TLV: %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_mdd_advanced_band_plan);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_abp_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_abp_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case MDD_ABP_SUB_BAND_COUNT:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_mdd_abp_sub_band_count, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case MDD_ABP_SUB_BAND_WIDTH:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_mdd_abp_sub_band_width, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_mdd_bpi_plus(tvbuff_t *tvb, packet_info *pinfo _U_, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  static int *const mdd_bpi_plus_cfg[] = {
    &hf_docsis_mdd_bpi_plus_cfg_eae,
    NULL
  };

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_mdd_bpi_plus_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, mdd_bpi_plus_vals, "Unknown TLV: %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_mdd_bpi_plus);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_bpi_plus_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_bpi_plus_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case MDD_BPI_PLUS_VERSION:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_mdd_bpi_plus_version, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case MDD_BPI_PLUS_CFG:
      if (tlv_length == 1)
        proto_tree_add_bitmask(tlv_tree, tvb, pos, hf_docsis_mdd_bpi_plus_cfg, ett_sub_tlv, mdd_bpi_plus_cfg, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static int
dissect_mdd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *mdd_item;
  proto_tree *mdd_tree;

  int pos;
  uint8_t type;
  uint32_t i, length;

  proto_tree *tlv_tree;
  proto_item *tlv_item;
  static int * const non_channel_events[] = {
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range,
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup,
      &hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power,
      NULL
  };

  col_set_str(pinfo->cinfo, COL_INFO, "MDD Message:");

  mdd_item = proto_tree_add_item(tree, proto_docsis_mdd, tvb, 0, -1, ENC_NA);
  mdd_tree = proto_item_add_subtree(mdd_item, ett_docsis_mdd);

  proto_tree_add_item (mdd_tree, hf_docsis_mdd_ccc, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_number_of_fragments, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_fragment_sequence_number, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mdd_tree, hf_docsis_mdd_current_channel_dcid, tvb, 3, 1, ENC_BIG_ENDIAN);

  /* TLVs... */
  pos = 4;
  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8(tvb, pos);
    length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(mdd_tree, hf_docsis_mdd_tlv, tvb, pos, length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(type, mdd_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_mdd_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch(type)
    {
    case DOWNSTREAM_ACTIVE_CHANNEL_LIST:
      dissect_mdd_ds_active_channel_list(tvb, pinfo, tlv_tree, pos, length );
      break;
    case MAC_DOMAIN_DOWNSTREAM_SERVICE_GROUP:
      dissect_mdd_ds_service_group(tvb, pinfo, tlv_tree, pos, length );
      break;
    case DOWNSTREAM_AMBIGUITY_RESOLUTION_FREQUENCY_LIST:
      for (i = 0; i < length; i+=4) {
        proto_tree_add_item (tlv_tree, hf_docsis_mdd_downstream_ambiguity_resolution_frequency, tvb, pos + i, 4, ENC_BIG_ENDIAN);
      }
      break;
    case RECEIVE_CHANNEL_PROFILE_REPORTING_CONTROL:
      dissect_mdd_channel_profile_reporting_control(tvb, pinfo, tlv_tree, pos, length );
      break;
    case IP_INITIALIZATION_PARAMETERS:
      dissect_mdd_ip_init_param(tvb, pinfo, tlv_tree, pos, length );
      break;
    case EARLY_AUTHENTICATION_AND_ENCRYPTION:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_early_authentication_and_encryption, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case UPSTREAM_ACTIVE_CHANNEL_LIST:
      dissect_mdd_upstream_active_channel_list(tvb, pinfo, tlv_tree, pos, length );
      break;
    case UPSTREAM_AMBIGUITY_RESOLUTION_CHANNEL_LIST:
      for (i = 0; i < length; i++) {
        proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id, tvb, pos + i , 1, ENC_BIG_ENDIAN);
      }
      break;
    case UPSTREAM_FREQUENCY_RANGE:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_frequency_range, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case SYMBOL_CLOCK_LOCKING_INDICATOR:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_symbol_clock_locking_indicator, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case CM_STATUS_EVENT_CONTROL:
      dissect_mdd_cm_status_event_control(tvb, pinfo, tlv_tree, pos, length );
      break;
    case UPSTREAM_TRANSMIT_POWER_REPORTING:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_upstream_transmit_power_reporting, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case DSG_DA_TO_DSID_ASSOCIATION_ENTRY:
      dissect_mdd_dsg_da_to_dsid(tvb, pinfo, tlv_tree, pos, length );
      break;
    case CM_STATUS_EVENT_ENABLE_NON_CHANNEL_SPECIFIC_EVENTS:
      proto_tree_add_bitmask(tlv_tree, tvb, pos, hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events, ett_sub_tlv, non_channel_events, ENC_BIG_ENDIAN);
      break;
    case EXTENDED_UPSTREAM_TRANSMIT_POWER_SUPPORT:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_extended_upstream_transmit_power_support, tvb, pos, 1, ENC_BIG_ENDIAN);
      break;
    case CMTS_DOCSIS_VERSION:
      dissect_mdd_docsis_version(tvb, pinfo, tlv_item, tlv_tree, pos, length);
      break;
    case CM_PERIODIC_MAINTENANCE_TIMEOUT_INDICATOR:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_cm_periodic_maintenance_timeout_indicator, tvb, pos, length, ENC_BIG_ENDIAN);
      break;
    case DLS_BROADCAST_AND_MULTICAST_DELIVERY_METHOD:
      proto_tree_add_item (tlv_tree, hf_docsis_mdd_dls_broadcast_and_multicast_delivery_method, tvb, pos, length, ENC_BIG_ENDIAN);
      break;
    case CM_STATUS_EVENT_ENABLE_FOR_DOCSIS_3_1_EVENTS:
      if (length == 4) {
        static int * const mdd_cm_status_event_d31[] = {
          &hf_docsis_mdd_cm_status_event_d31_ofdm_prof_fail,
          &hf_docsis_mdd_cm_status_event_d31_prim_down_chan_change,
          &hf_docsis_mdd_cm_status_event_d31_dpd_mismatch,
          &hf_docsis_mdd_cm_status_event_d31_deprecated,
          &hf_docsis_mdd_cm_status_event_d31_ncp_prof_fail,
          &hf_docsis_mdd_cm_status_event_d31_loss_fec_plc,
          &hf_docsis_mdd_cm_status_event_d31_ncp_prof_recover,
          &hf_docsis_mdd_cm_status_event_d31_fec_recover_on_plc,
          &hf_docsis_mdd_cm_status_event_d31_fec_recover_on_ofdm_prof,
          &hf_docsis_mdd_cm_status_event_d31_ofdma_prof_fail,
          &hf_docsis_mdd_cm_status_event_d31_map_stor_overflow_ind,
          &hf_docsis_mdd_cm_status_event_d31_ofdm_map_stor_almost_full_ind,
          &hf_docsis_mdd_cm_status_event_d31_reserved,
          NULL
        };
        proto_tree_add_bitmask_list(tlv_tree, tvb, pos, length, mdd_cm_status_event_d31, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DIPLEXER_BAND_EDGE:
      dissect_mdd_diplexer_band_edge(tvb, pinfo, tlv_tree, pos, length );
      break;
    case ADVANCED_BAND_PLAN:
      dissect_mdd_advanced_band_plan(tvb, pinfo, tlv_item, tlv_tree, pos, length);
      break;
    case MDD_BPI_PLUS:
      dissect_mdd_bpi_plus(tvb, pinfo, tlv_item, tlv_tree, pos, length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown MDD TLV type: %u", type);
      break;
    }

    pos += length;
  }

  return tvb_captured_length(tvb);
}

static int
dissect_bintrngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *bintrngreq_item;
  proto_tree *bintrngreq_tree;
  uint8_t md_ds_sg_id;
  uint16_t offset = 0;

  md_ds_sg_id = tvb_get_uint8 (tvb, 1);

  col_add_fstr (pinfo->cinfo, COL_INFO, "Bonded Initial Ranging Request: MD-DS-SG-ID = %u (0x%X)",
                md_ds_sg_id, md_ds_sg_id );

  bintrngreq_item = proto_tree_add_item(tree, proto_docsis_bintrngreq, tvb, offset, -1, ENC_NA);
  bintrngreq_tree = proto_item_add_subtree (bintrngreq_item, ett_docsis_bintrngreq);
  proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_capflags, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item( bintrngreq_tree, hf_docsis_bintrngreq_capflags_frag, tvb, offset, 1, ENC_BIG_ENDIAN );
  proto_tree_add_item( bintrngreq_tree, hf_docsis_bintrngreq_capflags_encrypt, tvb, offset, 1, ENC_BIG_ENDIAN );
  offset++;
  proto_tree_add_item (bintrngreq_tree, hf_docsis_bintrngreq_mddsgid, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item (bintrngreq_tree, hf_docsis_mgt_down_chid, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item (bintrngreq_tree, hf_docsis_mgt_upstream_chid, tvb, offset, 1, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static int
dissect_type35ucd(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_type35ucd, MGT_TYPE35UCD);
}

static int
dissect_dbcreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *dbcreq_item, *reassembled_item;
  proto_tree *dbcreq_tree, *reassembled_tree;
  uint32_t transid, number_of_fragments, fragment_sequence_number, id;
  tvbuff_t *next_tvb;

  dbcreq_item = proto_tree_add_item(tree, proto_docsis_dbcreq, tvb, 0, -1, ENC_NA);
  dbcreq_tree = proto_item_add_subtree (dbcreq_item, ett_docsis_dbcreq);
  proto_tree_add_item_ret_uint(dbcreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint( dbcreq_tree, hf_docsis_dbcreq_number_of_fragments, tvb, 2, 1, ENC_BIG_ENDIAN, &number_of_fragments);
  proto_tree_add_item_ret_uint( dbcreq_tree, hf_docsis_dbcreq_fragment_sequence_number, tvb, 3, 1, ENC_BIG_ENDIAN, &fragment_sequence_number);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Bonding Change Request: Tran-Id = %u ", transid);
  col_set_fence(pinfo->cinfo, COL_INFO);

  if(number_of_fragments > 1) {
     pinfo->fragmented = true;

     id = (MGT_DBC_REQ << 24) + transid;
     fragment_head* reassembled_tlv = NULL;
     reassembled_tlv = fragment_add_seq_check(&docsis_tlv_reassembly_table,
                                  tvb, 4, pinfo,
                                  id, NULL, /* ID for fragments belonging together */
                                  fragment_sequence_number - 1, /* Sequence number starts at 0 */
                                  tvb_reported_length_remaining(tvb, 4), /* fragment length - to the end */
                                  (fragment_sequence_number != number_of_fragments)); /* More fragments? */

     if (reassembled_tlv) {
       tvbuff_t *tlv_tvb = NULL;

       reassembled_item = proto_tree_add_item(dbcreq_tree, hf_docsis_tlv_reassembled, tvb, 0, -1, ENC_NA);
       reassembled_tree = proto_item_add_subtree (reassembled_item, ett_docsis_tlv_reassembled );


       tlv_tvb = process_reassembled_data(tvb, 4, pinfo, "Reassembled TLV", reassembled_tlv, &docsis_tlv_frag_items,
                                                  NULL, reassembled_tree);

       if (tlv_tvb && tvb_reported_length(tlv_tvb) > 0) {
         call_dissector (docsis_tlv_handle, tlv_tvb, pinfo, reassembled_tree);
       }
     }

  } else {
    /* Call Dissector for Appendix C TLVs */
    next_tvb = tvb_new_subset_remaining (tvb, 4);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcreq_tree);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_dbcrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *dbcrsp_item;
  proto_tree *dbcrsp_tree;
  uint32_t transid, confcode;
  tvbuff_t *next_tvb;

  dbcrsp_item = proto_tree_add_item(tree, proto_docsis_dbcrsp, tvb, 0, -1, ENC_NA);
  dbcrsp_tree = proto_item_add_subtree (dbcrsp_item, ett_docsis_dbcrsp);
  proto_tree_add_item_ret_uint(dbcrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint( dbcrsp_tree, hf_docsis_dbcrsp_conf_code, tvb, 2, 1, ENC_BIG_ENDIAN, &confcode);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Bonding Change Response: Tran-Id = %u (%s) ", transid,
                val_to_str_ext (confcode, &docsis_conf_code_ext, "%d"));

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 3);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dbcack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *dbcack_item;
  proto_tree *dbcack_tree = NULL;
  uint16_t transid;
  tvbuff_t *next_tvb;

  transid = tvb_get_ntohs (tvb, 0);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "Dynamic Bonding Change Acknowledge: Tran-Id = %u ", transid);

  dbcack_item = proto_tree_add_item(tree, proto_docsis_dbcack, tvb, 0, -1, ENC_NA);
  dbcack_tree = proto_item_add_subtree (dbcack_item, ett_docsis_dbcack);
  proto_tree_add_item (dbcack_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN);

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, dbcack_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_dpvreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dpvreq_tree;
  uint32_t transid, dschan;

  it = proto_tree_add_item(tree, proto_docsis_dpvreq, tvb, 0, -1, ENC_NA);
  dpvreq_tree = proto_item_add_subtree (it, ett_docsis_dpvreq);
  proto_tree_add_item_ret_uint (dpvreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dpvreq_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &dschan);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "DOCSIS Path Verify Request: Transaction ID = %u DS-Ch %d",
                transid, dschan);

  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_flags, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_us_sf, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_n, tvb, 8, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_start, tvb, 10, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_end, tvb, 11, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_ts_start, tvb, 12, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvreq_tree, hf_docsis_dpv_ts_end, tvb, 16, 4, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static int
dissect_dpvrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *dpvrsp_tree = NULL;
  uint32_t transid, dschan;

  it = proto_tree_add_item (tree, proto_docsis_dpvrsp, tvb, 0, -1, ENC_NA);
  dpvrsp_tree = proto_item_add_subtree (it, ett_docsis_dpvrsp);
  proto_tree_add_item_ret_uint (dpvrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);
  proto_tree_add_item_ret_uint (dpvrsp_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &dschan);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "DOCSIS Path Verify Response: Transaction ID = %u DS-Ch %d",
                transid, dschan);

  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_flags, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_us_sf, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_n, tvb, 8, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_start, tvb, 10, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_end, tvb, 11, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_ts_start, tvb, 12, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (dpvrsp_tree, hf_docsis_dpv_ts_end, tvb, 16, 4, ENC_BIG_ENDIAN);

  return tvb_captured_length(tvb);
}

static void
dissect_cmstatus_status_event_tlv (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  uint16_t pos = 0;
  uint8_t type;
  uint32_t length;

  it = proto_tree_add_item(tree, hf_docsis_cmstatus_status_event_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_cmstatus_status_event_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, -1,
                                            ett_docsis_cmstatus_status_event_tlvtlv, &tlv_item,
                                            val_to_str(type, cmstatus_status_event_tlv_vals,
                                                       "Unknown Status Event TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_cmstatus_status_event_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlvtlv_tree, hf_docsis_cmstatus_status_event_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case EVENT_DS_CH_ID:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmstatus_status_event_ds_ch_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_US_CH_ID:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmstatus_status_event_us_ch_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_DSID:
      if (length == 3)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmstatus_status_event_dsid, tvb, pos, 3, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_MAC_ADDRESS:
      if (length == 6)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmstatus_status_event_mac_address, tvb, pos, 6, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_DS_OFDM_PROFILE_ID:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmstatus_status_event_ds_ofdm_profile_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_US_OFDMA_PROFILE_ID:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmstatus_status_event_us_ofdma_profile_id, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    case EVENT_DESCR:
      if (length >= 1 && length <= 80)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmstatus_status_event_descr, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    } /* switch */
      pos += length;
  } /* while */
}

static void
dissect_cmstatus_tlv (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  uint16_t pos = 0;
  uint8_t type;
  uint32_t length;
  tvbuff_t* next_tvb;

  it = proto_tree_add_item(tree, hf_docsis_cmstatus_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_cmstatus_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, -1,
                                            ett_docsis_cmstatus_tlvtlv, &tlv_item,
                                            val_to_str(type, cmstatus_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_cmstatus_type, tvb, pos, 1, type);
    pos++;
    proto_tree_add_item_ret_uint (tlvtlv_tree, hf_docsis_cmstatus_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case STATUS_EVENT:
      next_tvb = tvb_new_subset_length(tvb, pos, length);
      dissect_cmstatus_status_event_tlv (next_tvb, pinfo, tlvtlv_tree);
      break;

    } /* switch */
      pos += length;
  } /* while */
}

static void
dissect_cmstatus_common (tvbuff_t * tvb, proto_tree * tree)
{
  uint8_t event_type;

  event_type = tvb_get_uint8 (tvb, 2);
  switch (event_type)
  {
  case SEC_CH_MDD_TIMEOUT:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_mdd_t, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case QAM_FEC_LOCK_FAILURE:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_qfl_f, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case SEQ_OUT_OF_RANGE:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_s_o, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case SEC_CH_MDD_RECOVERY:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_mdd_r, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case QAM_FEC_LOCK_RECOVERY:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_qfl_r, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case T4_TIMEOUT:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_t4_t, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case T3_RETRIES_EXCEEDED:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_t3_e, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case SUCCESS_RANGING_AFTER_T3_RETRIES_EXCEEDED:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_rng_s, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case CM_ON_BATTERY:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_cm_b, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case CM_ON_AC_POWER:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_cm_a, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case MAC_REMOVAL_EVENT:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_mac_removal, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case DS_OFDM_PROFILE_FAILURE:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_ds_ofdm_profile_failure, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case PRIMARY_DOWNSTREAM_CHANGE:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_prim_ds_change, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case DPD_MISMATCH:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_dpd_mismatch, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case NCP_PROFILE_FAILURE:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_ncp_profile_failure, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case PLC_FAILURE:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_plc_failure, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case NCP_PROFILE_RECOVERY:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_ncp_profile_recovery, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case PLC_RECOVERY:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_plc_recovery, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case OFDM_PROFILE_RECOVERY:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_ofdm_profile_recovery, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case OFDMA_PROFILE_FAILURE:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_ofdma_profile_failure, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case MAP_STORAGE_OVERFLOW_INDICATOR:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_map_storage_overflow_indicator, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  case MAP_STORAGE_ALMOST_FULL_INDICATOR:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_map_storage_almost_full_indicator, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;

  default:
    proto_tree_add_item (tree, hf_docsis_cmstatus_e_t_unknown, tvb, 2, 1, ENC_BIG_ENDIAN);
    break;
  } /* switch */
  return;
}

static int
dissect_cmstatus (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *cmstatus_tree;
  uint32_t transid;
  tvbuff_t* next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_cmstatus, tvb, 0, -1, ENC_NA);
  cmstatus_tree = proto_item_add_subtree (it, ett_docsis_cmstatus);
  proto_tree_add_item_ret_uint (cmstatus_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO, "CM-STATUS Report: Transaction ID = %u", transid);

  dissect_cmstatus_common (tvb, cmstatus_tree);

  /* Call Dissector TLVs */
  next_tvb = tvb_new_subset_remaining(tvb, 3);
  dissect_cmstatus_tlv(next_tvb, pinfo, cmstatus_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_cmstatusack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *cmstatus_tree;
  uint32_t transid;

  it = proto_tree_add_item(tree, proto_docsis_cmstatusack, tvb, 0, -1, ENC_NA);
  cmstatus_tree = proto_item_add_subtree (it, ett_docsis_cmstatusack);
  proto_tree_add_item_ret_uint (cmstatus_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO, "CM-STATUS Report Acknowledge: Transaction ID = %u", transid);

  dissect_cmstatus_common (tvb, cmstatus_tree);

  return tvb_captured_length(tvb);
}

static void
dissect_ds_event(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *event_tree;
  proto_item *event_item, *tlv_len_item;
  int pos = start;

  while (pos < (start + len))
  {
    type = tvb_get_uint8 (tvb, pos);
    event_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_cmctrl_tlv_ds_event, &event_item,
                                            val_to_str(type, cmctrlreq_ds_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (event_tree, hf_docsis_cmctrl_ds_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (event_tree, hf_docsis_cmctrl_ds_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(event_item, length + 2);

    switch (type)
    {
    case DS_EVENT_CH_ID:
      if (length == 1)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_ds_event_ch_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case DS_EVENT_MASK:
      if (length == 2)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_ds_event_mask, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }          /* switch */

    pos += length;
  }            /* while */
}

static void
dissect_us_event(tvbuff_t * tvb, packet_info* pinfo, proto_tree *tree, int start, uint16_t len)
{
  uint8_t type;
  uint32_t length;
  proto_tree *event_tree;
  proto_item *event_item, *tlv_len_item;
  int pos = start;

  while (pos < (start + len))
  {
    type = tvb_get_uint8 (tvb, pos);
    event_tree = proto_tree_add_subtree(tree, tvb, pos, -1,
                                            ett_docsis_cmctrl_tlv_us_event, &event_item,
                                            val_to_str(type, cmctrlreq_us_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (event_tree, hf_docsis_cmctrlreq_us_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (event_tree, hf_docsis_cmctrlreq_us_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(event_item, length + 2);

    switch (type)
    {
    case US_EVENT_CH_ID:
      if (length == 1)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_us_event_ch_id, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case US_EVENT_MASK:
      if (length == 2)
      {
        proto_tree_add_item (event_tree, hf_docsis_cmctrl_us_event_mask, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    }                   /* switch */
      pos += length;
  }                     /* while */
}

static void
dissect_cmctrlreq_tlv(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  uint16_t pos = 0;
  uint8_t type;
  uint32_t length;

  it = proto_tree_add_item(tree, hf_docsis_cmctrlreq_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_cmctrlreq_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    length = tvb_get_uint8 (tvb, pos + 1);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, length + 2,
                                            ett_docsis_cmctrlreq_tlvtlv, &tlv_item,
                                            val_to_str(type, cmctrlreq_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_cmctrlreq_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrlreq_length, tvb, pos, 1, ENC_NA);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case CM_CTRL_MUTE:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrl_tlv_mute, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_MUTE_TIMEOUT:
      if (length == 4 || length == 1) /* response TLV always with len 1 */
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrl_tlv_mute_timeout, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_REINIT:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrl_tlv_reinit, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_DISABLE_FWD:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrl_tlv_disable_fwd, tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CM_CTRL_DS_EVENT:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrl_tlv_ds_event, tvb, pos, length, ENC_NA);
      }
      else
      {
        dissect_ds_event(tvb, pinfo, tlvtlv_tree, pos, length);
      }
      break;
    case CM_CTRL_US_EVENT:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrl_tlv_us_event, tvb, pos, length, ENC_NA);
      }
      else
      {
        dissect_us_event(tvb, pinfo, tlvtlv_tree, pos, length);
      }
      break;
    case CM_CTRL_EVENT:
      if (length == 2 || length == 1) /* response TLV always with len 1 */
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_cmctrl_tlv_event, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;

    } /* switch */

    pos += length;
  }
}

static int
dissect_cmctrlreq(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *cmctrlreq_tree;
  uint32_t transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item (tree, proto_docsis_cmctrlreq, tvb, 0, -1, ENC_NA);
  cmctrlreq_tree = proto_item_add_subtree (it, ett_docsis_cmctrlreq);
  proto_tree_add_item_ret_uint (cmctrlreq_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "CM Control Request: Transaction ID = %u", transid);

  next_tvb = tvb_new_subset_remaining(tvb, 2);
  dissect_cmctrlreq_tlv(next_tvb, pinfo, cmctrlreq_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_cmctrlrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *cmctrlrsp_tree;
  uint32_t transid;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, proto_docsis_cmctrlrsp, tvb, 0, -1, ENC_NA);
  cmctrlrsp_tree = proto_item_add_subtree (it, ett_docsis_cmctrlrsp);
  proto_tree_add_item_ret_uint (cmctrlrsp_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &transid);

  col_add_fstr (pinfo->cinfo, COL_INFO,
                "CM Control Response: Transaction ID = %u", transid);

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 2);
  dissect_cmctrlreq_tlv(next_tvb, pinfo, cmctrlrsp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regreqmp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *regreqmp_tree;
  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_INFO, "REG-REQ-MP Message:");

  it = proto_tree_add_item(tree, proto_docsis_regreqmp, tvb, 0, -1, ENC_NA);
  regreqmp_tree = proto_item_add_subtree (it, ett_docsis_regreqmp);

  proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_sid, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_number_of_fragments, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (regreqmp_tree, hf_docsis_regreqmp_fragment_sequence_number, tvb, 3, 1, ENC_BIG_ENDIAN);

  /* Call Dissector for Appendix C TLVs */
  next_tvb = tvb_new_subset_remaining (tvb, 4);
  call_dissector (docsis_tlv_handle, next_tvb, pinfo, regreqmp_tree);
  return tvb_captured_length(tvb);
}

static int
dissect_regrspmp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it, *reassembled_item;
  proto_tree *regrspmp_tree, *reassembled_tree;
  unsigned sid, number_of_fragments, fragment_sequence_number, id;

  tvbuff_t *next_tvb;

  col_set_str(pinfo->cinfo, COL_INFO, "REG-RSP-MP Message");
  /* Make sure embedded UCD does not overwrite REGRSPMP info */
  col_set_fence(pinfo->cinfo, COL_INFO);

  it = proto_tree_add_item(tree, proto_docsis_regrspmp, tvb, 0, -1, ENC_NA);
  regrspmp_tree = proto_item_add_subtree (it, ett_docsis_regrspmp);

  proto_tree_add_item_ret_uint (regrspmp_tree, hf_docsis_regrspmp_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item (regrspmp_tree, hf_docsis_regrspmp_response, tvb, 2, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (regrspmp_tree, hf_docsis_regrspmp_number_of_fragments, tvb, 3, 1, ENC_BIG_ENDIAN, &number_of_fragments);
  proto_tree_add_item_ret_uint (regrspmp_tree, hf_docsis_regrspmp_fragment_sequence_number, tvb, 4, 1, ENC_BIG_ENDIAN, &fragment_sequence_number);

  col_add_fstr(pinfo->cinfo, COL_INFO, " (fragment %d):", fragment_sequence_number);
  /* Make sure embedded UCD does not overwrite REGRSPMP info */
  col_set_fence(pinfo->cinfo, COL_INFO);

  if(number_of_fragments > 1) {
     pinfo->fragmented = true;

     id = (MGT_REG_RSP << 24) + sid;
     fragment_head* reassembled_tlv = NULL;
     reassembled_tlv = fragment_add_seq_check(&docsis_tlv_reassembly_table,
                                  tvb, 5, pinfo,
                                  id, NULL, /* ID for fragments belonging together */
                                  fragment_sequence_number - 1, /* Sequence number starts at 0 */
                                  tvb_reported_length_remaining(tvb, 5), /* fragment length - to the end */
                                  (fragment_sequence_number != number_of_fragments)); /* More fragments? */

     if (reassembled_tlv) {
       tvbuff_t *tlv_tvb = NULL;

       reassembled_item = proto_tree_add_item(regrspmp_tree, hf_docsis_tlv_reassembled, tvb, 0, -1, ENC_NA);
       reassembled_tree = proto_item_add_subtree (reassembled_item, ett_docsis_tlv_reassembled );


       tlv_tvb = process_reassembled_data(tvb, 5, pinfo, "Reassembled TLV", reassembled_tlv, &docsis_tlv_frag_items,
                                                  NULL, reassembled_tree);

       if (tlv_tvb && tvb_reported_length(tlv_tvb) > 0) {
         call_dissector (docsis_tlv_handle, tlv_tvb, pinfo, reassembled_tree);
       }
     }

  } else {
    /* Call Dissector for Appendix C TLVs */
    next_tvb = tvb_new_subset_remaining (tvb, 5);
    call_dissector (docsis_tlv_handle, next_tvb, pinfo, regrspmp_tree);
  }

  return tvb_captured_length(tvb);
}

static void
dissect_emrsp_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  unsigned pos = 0;
  unsigned length;
  uint8_t type;

  it = proto_tree_add_item(tree, hf_docsis_emrsp_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_emrsp_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    length = tvb_get_uint8 (tvb, pos + 1);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, length + 2,
                                            ett_docsis_emrsp_tlvtlv, &tlv_item,
                                            val_to_str(type, emrsp_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_item (tlvtlv_tree, hf_docsis_emrsp_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    pos++;
    proto_tree_add_item (tlvtlv_tree, hf_docsis_emrsp_tlv_length, tvb, pos, 1, ENC_BIG_ENDIAN);
    pos++;


    switch (type)
    {
    case EM_HOLDOFF_TIMER:
      proto_tree_add_item (tlvtlv_tree, hf_docsis_emrsp_tlv_holdoff_timer, tvb, pos, length, ENC_BIG_ENDIAN);
      break;
    default:
      proto_tree_add_item (tlvtlv_tree, hf_docsis_emrsp_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", type);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static int
dissect_emreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *em_tree;

  uint32_t trans_id, req_power_mode;

  it = proto_tree_add_item(tree, proto_docsis_emreq, tvb, 0, -1, ENC_NA);
  em_tree = proto_item_add_subtree (it, ett_docsis_emreq);
  proto_tree_add_item_ret_uint (em_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &trans_id);
  proto_tree_add_item_ret_uint (em_tree, hf_docsis_emreq_req_power_mode, tvb, 2, 1, ENC_BIG_ENDIAN, &req_power_mode);
  proto_tree_add_item (em_tree, hf_docsis_emreq_reserved, tvb, 3, 1, ENC_BIG_ENDIAN);

  col_add_fstr (pinfo->cinfo, COL_INFO, "EM-REQ: Transaction ID: %u, Requested Power Mode: %s (%u)", trans_id,
                              val_to_str(req_power_mode, emreq_req_power_mode_vals, "Unknown Requested Power Mode (%u)"), req_power_mode);

  return tvb_captured_length(tvb);
}

static int
dissect_emrsp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *em_tree;
  tvbuff_t *next_tvb;

  uint32_t trans_id, rsp_code;

  it = proto_tree_add_item(tree, proto_docsis_emrsp, tvb, 0, -1, ENC_NA);
  em_tree = proto_item_add_subtree (it, ett_docsis_emrsp);
  proto_tree_add_item_ret_uint (em_tree, hf_docsis_mgt_tranid, tvb, 0, 2, ENC_BIG_ENDIAN, &trans_id);
  proto_tree_add_item_ret_uint (em_tree, hf_docsis_emrsp_rsp_code, tvb, 2, 1, ENC_BIG_ENDIAN, &rsp_code);
  proto_tree_add_item (em_tree, hf_docsis_emrsp_reserved, tvb, 3, 1, ENC_BIG_ENDIAN);

  col_add_fstr (pinfo->cinfo, COL_INFO, "EM-RSP: Transaction ID: %u, Response Code: %s (%u)", trans_id,
                              val_to_str(rsp_code, emrsp_rsp_code_vals, "Unknown Response Code (%u)"), rsp_code);

  /* Call Dissector TLVs */
  if(tvb_reported_length_remaining(tvb, 4) > 0 )
  {
    next_tvb = tvb_new_subset_remaining(tvb, 4);
    dissect_emrsp_tlv(next_tvb, pinfo, em_tree);
  }

  return tvb_captured_length(tvb);
}

static void
dissect_subcarrier_assignment_range_list(tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree, uint16_t pos, uint32_t len)
{
  proto_item* type_item;
  uint32_t i, subcarrier_assignment_type;

  type_item = proto_tree_add_item_ret_uint (tree, hf_docsis_ocd_tlv_subc_assign_type, tvb, pos, 1, ENC_BIG_ENDIAN, &subcarrier_assignment_type);
  proto_tree_add_item (tree, hf_docsis_ocd_tlv_subc_assign_value, tvb, pos, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (tree, hf_docsis_ocd_subc_assign_subc_type, tvb, pos, 1, ENC_BIG_ENDIAN);
  pos++;

  switch (subcarrier_assignment_type) {
    case SUBCARRIER_ASSIGNMENT_RANGE_CONT:
    case SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1:
      proto_tree_add_item (tree, hf_docsis_ocd_subc_assign_range, tvb, pos, 4, ENC_BIG_ENDIAN);
      break;
    case SUBCARRIER_ASSIGNMENT_LIST:
      for (i = 0; i < len/2; ++i) {
        proto_tree_add_item (tree, hf_docsis_ocd_subc_assign_index, tvb, pos, 2, ENC_BIG_ENDIAN);
        pos += 2;
      }
      break;
    default:
      expert_add_info_format(pinfo, type_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown subcarrier assignment type %d", subcarrier_assignment_type);
      break;
  }
}

static void
dissect_ocd_tlv (tvbuff_t * tvb, packet_info* pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  uint16_t pos = 0;
  uint8_t type;
  uint32_t length;

  it = proto_tree_add_item(tree, hf_docsis_ocd_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_ocd_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, -1,
                                            ett_docsis_ocd_tlvtlv, &tlv_item,
                                            val_to_str(type, ocd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_ocd_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item_ret_uint (tlvtlv_tree, hf_docsis_ocd_length, tvb, pos, 1, ENC_NA, &length);
    pos++;
    proto_item_set_len(tlv_item, length + 2);

    switch (type)
    {
    case DISCRETE_FOURIER_TRANSFORM_SIZE:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_four_trans_size, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case CYCLIC_PREFIX:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_cycl_pref, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case ROLL_OFF:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_roll_off, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OFDM_SPECTRUM_LOCATION:
      if (length == 4)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_ofdm_spec_loc, tvb, pos, 4, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case TIME_INTERLEAVING_DEPTH:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_time_int_depth, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case SUBCARRIER_ASSIGNMENT_RANGE_LIST:
      if (length >= 5)
      {
        dissect_subcarrier_assignment_range_list(tvb, pinfo, tlvtlv_tree, pos, length);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case PRIMARY_CAPABILITY_INDICATOR:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_prim_cap_ind, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case FDX_INDICATOR:
      if (length == 1)
      {
        proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_fdx_ind, tvb, pos, 1, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    default:
      proto_tree_add_item (tlvtlv_tree, hf_docsis_ocd_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static int
dissect_ocd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  proto_item *it;
  proto_tree *ocd_tree;
  tvbuff_t *tlv_tvb = NULL;
  uint32_t downstream_channel_id, configuration_change_count, id;

  it = proto_tree_add_item(tree, proto_docsis_ocd, tvb, 0, -1, ENC_NA);
  ocd_tree = proto_item_add_subtree (it, ett_docsis_ocd);

  proto_tree_add_item_ret_uint (ocd_tree, hf_docsis_mgt_down_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint (ocd_tree, hf_docsis_ocd_ccc, tvb, 1, 1, ENC_BIG_ENDIAN, &configuration_change_count);

  col_add_fstr (pinfo->cinfo, COL_INFO, "OCD: DS CH ID: %u, CCC: %u", downstream_channel_id, configuration_change_count);

  id = (downstream_channel_id << 16) + configuration_change_count;
  tlv_tvb = dissect_multipart(tvb, pinfo, ocd_tree, data, MGT_OCD, id, 2);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_ocd_tlv(tlv_tvb, pinfo, ocd_tree);
  return tvb_captured_length(tvb);
}

static void
dissect_dpd_subcarrier_assignment_range_list(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, unsigned pos, unsigned len)
{
  uint32_t i, subcarrier_assignment_type;
  proto_item* type_item;
  unsigned modulation;

  type_item = proto_tree_add_item_ret_uint (tree, hf_docsis_dpd_tlv_subc_assign_type, tvb, pos, 1, ENC_BIG_ENDIAN, &subcarrier_assignment_type);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_value, tvb, pos, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_reserved, tvb, pos, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (tree, hf_docsis_dpd_tlv_subc_assign_modulation, tvb, pos, 1, ENC_BIG_ENDIAN, &modulation);
  col_append_str(pinfo->cinfo, COL_INFO, val_to_str(modulation, docsis_dpd_subc_assign_modulation_str, "unknown(%u)"));
  pos++;

  switch (subcarrier_assignment_type)
  {
    case SUBCARRIER_ASSIGNMENT_RANGE_CONT:
    case SUBCARRIER_ASSIGNMENT_RANGE_SKIPBY1:
      proto_tree_add_item (tree, hf_docsis_dpd_subc_assign_range, tvb, pos, 4, ENC_BIG_ENDIAN);
      break;
    case SUBCARRIER_ASSIGNMENT_LIST:
      for (i = 0; i < len/2; ++i) {
        proto_tree_add_item (tree, hf_docsis_dpd_subc_assign_index, tvb, pos, 2, ENC_BIG_ENDIAN);
        pos += 2;
      }
      break;
    default:
      expert_add_info_format(pinfo, type_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown subcarrier assignment type: %u", subcarrier_assignment_type);
      break;
  }
}

static void
dissect_dpd_subcarrier_assignment_vector(tvbuff_t * tvb, proto_tree * tree, unsigned start, unsigned len)
{
  uint32_t subcarrier_assignment_vector_oddness;
  unsigned vector_index;

  proto_tree_add_item_ret_uint (tree, hf_docsis_dpd_tlv_subc_assign_vector_oddness, tvb, start, 1, ENC_BIG_ENDIAN, &subcarrier_assignment_vector_oddness);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_reserved, tvb, start, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_subc_start, tvb, start, 2, ENC_BIG_ENDIAN);

  for(vector_index = 0; vector_index < len; ++vector_index)
  {
    proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd, tvb, start + 2 + vector_index, 1, ENC_BIG_ENDIAN);
    if (!((vector_index == len -1) && subcarrier_assignment_vector_oddness))
    {
      proto_tree_add_item (tree, hf_docsis_dpd_tlv_subc_assign_vector_modulation_even, tvb, start + 2 + vector_index, 1, ENC_BIG_ENDIAN);
    }
  }
}


static void
dissect_dpd_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  unsigned pos = 0;
  unsigned length;
  uint8_t type;
  unsigned first_subc_assign_list = 1;

  it = proto_tree_add_item(tree, hf_docsis_dpd_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_dpd_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    if ( type == SUBCARRIER_ASSIGNMENT_VECTOR)
    {
      /* For this type, length is 2 bytes instead of 1 */
      length = tvb_get_ntohs (tvb, pos + 1);
    } else {
      length = tvb_get_uint8 (tvb, pos + 1);
    }

    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, length + 2,
                                            ett_docsis_dpd_tlvtlv, &tlv_item,
                                            val_to_str(type, dpd_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_dpd_type, tvb, pos, 1, type);
    pos++;
    if (type == SUBCARRIER_ASSIGNMENT_VECTOR)
    {
      /* For this type, length is 2 bytes instead of 1 */
      tlv_len_item = proto_tree_add_item (tlvtlv_tree, hf_docsis_dpd_length, tvb, pos, 2, ENC_BIG_ENDIAN);
      pos += 2;
    } else {
      tlv_len_item = proto_tree_add_item (tlvtlv_tree, hf_docsis_dpd_length, tvb, pos, 1, ENC_NA);
      pos++;
    }

    switch (type)
    {
    case SUBCARRIER_ASSIGNMENT_RANGE_LIST:
      if (length >= 5)
      {
        if(first_subc_assign_list) {
          col_append_str(pinfo->cinfo, COL_INFO, ", Modulation: ");
          first_subc_assign_list = 0;
        } else {
          col_append_str(pinfo->cinfo, COL_INFO, " | ");
        }
        dissect_dpd_subcarrier_assignment_range_list(tvb, pinfo, tlvtlv_tree, pos, length);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case SUBCARRIER_ASSIGNMENT_VECTOR:
      if (length >=2)
      {
        dissect_dpd_subcarrier_assignment_vector(tvb, tlvtlv_tree, pos, length);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    default:
      proto_tree_add_item (tlvtlv_tree, hf_docsis_dpd_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", type);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static int
dissect_dpd (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *dpd_tree;
  tvbuff_t *next_tvb;

  uint32_t downstream_channel_id, profile_identifier, configuration_change_count;

  it = proto_tree_add_item(tree, proto_docsis_dpd, tvb, 0, -1, ENC_NA);
  dpd_tree = proto_item_add_subtree (it, ett_docsis_dpd);
  proto_tree_add_item_ret_uint (dpd_tree, hf_docsis_mgt_down_chid, tvb, 0, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint (dpd_tree, hf_docsis_dpd_prof_id, tvb, 1, 1, ENC_BIG_ENDIAN, &profile_identifier);
  proto_tree_add_item_ret_uint (dpd_tree, hf_docsis_dpd_ccc, tvb, 2, 1, ENC_BIG_ENDIAN, &configuration_change_count);

  col_add_fstr (pinfo->cinfo, COL_INFO, "DPD: DS CH ID: %u, Profile ID: %u, CCC: %u", downstream_channel_id, profile_identifier, configuration_change_count);

  /* Call Dissector TLVs */
  next_tvb = tvb_new_subset_remaining(tvb, 3);
  dissect_dpd_tlv(next_tvb, pinfo, dpd_tree);

  return tvb_captured_length(tvb);
}

static int
dissect_type51ucd(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  return dissect_any_ucd(tvb, pinfo, tree, proto_docsis_type51ucd, MGT_TYPE51UCD);
}

static void
dissect_optreq_tlv_rxmer_thresholding_parameters (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  unsigned pos = 0;
  unsigned length;
  uint8_t type;

  it = proto_tree_add_item(tree, hf_docsis_optreq_tlv_rxmer_thresh_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_optreq_tlv_rxmer_thresh_params);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    length = tvb_get_uint8 (tvb, pos + 1);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, length + 2,
                                            ett_docsis_optreq_tlv_rxmer_thresh_params_tlv, &tlv_item,
                                            val_to_str(type, optreq_tlv_rxmer_thresh_params_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_optreq_xmer_thresh_params_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item (tlvtlv_tree, hf_docsis_optreq_xmer_thresh_params_length, tvb, pos, 1, ENC_NA);
    pos++;


    switch (type)
    {
    case OPT_REQ_RXMER_THRESH_PARAMS_MODULATION_ORDER:
      if (length == 1)
      {
        proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_rxmer_thresh_data_mod_order, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    default:
      proto_tree_add_item (tlvtlv_tree, hf_docsis_optreq_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", type);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static void
dissect_optreq_tlv_trigger_definition (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item, *subtree_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  unsigned pos = 0;
  unsigned length, measurement_duration;
  uint8_t type;

  it = proto_tree_add_item(tree, hf_docsis_optreq_tlv_trigger_definition_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_optreq_tlv_trigger_definition_params);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    length = tvb_get_uint8 (tvb, pos + 1);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, length + 2,
                                            ett_docsis_optreq_tlv_trigger_definition_params_tlv, &tlv_item,
                                            val_to_str(type, optreq_tlv_trigger_definition_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_data_type,
                         tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item (tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_data_length,
                                        tvb, pos, 1, ENC_NA);
    pos++;

    switch (type)
    {
    case OPT_REQ_TRIGGER_DEFINITION_TRIGGER_TYPE:
      if (length == 1)
      {
        proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_trigger_type, tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OPT_REQ_TRIGGER_DEFINITION_MEASUREMENT_DURATION:
      if (length == 2)
      {
        subtree_item = proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_measure_duration,
                                           tvb, pos, length, ENC_BIG_ENDIAN);
        proto_item_append_text(subtree_item, " OFDM Symbols");
        measurement_duration = tvb_get_uint8 (tvb, pos);
        if (measurement_duration > 1024)
        {
          expert_add_info_format(pinfo, subtree_item, &ei_docsis_mgmt_opt_req_trigger_def_measure_duration,
                                 "Measurement duration exceeds 1024 OFDM symbols: %u", measurement_duration);
        }
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OPT_REQ_TRIGGER_DEFINITION_TRIGGERING_SID:
      if (length == 2)
      {
        proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_triggering_sid,
                            tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OPT_REQ_TRIGGER_DEFINITION_US_CHANNEL_ID:
      if (length == 1)
      {
        proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_us_chan_id,
                            tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OPT_REQ_TRIGGER_DEFINITION_OUDP_SOUND_AMBIG_OFFSET:
      if (length == 4)
      {
        subtree_item = proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_sound_ambig_offset,
                            tvb, pos, length, ENC_BIG_ENDIAN);
        proto_item_append_text(subtree_item, " DOCSIS time ticks (10.24 MHz)");
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OPT_REQ_TRIGGER_DEFINITION_RXMER_TO_REPORT:
      if (length == 1)
      {
        proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_rx_mer_to_report,
                            tvb, pos, length, ENC_NA);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OPT_REQ_TRIGGER_DEFINITION_START_TIME:
      if (length == 4)
      {
        proto_tree_add_item(tlvtlv_tree, hf_docsis_optreq_tlv_trigger_definition_start_time,
                            tvb, pos, length, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    default:
      proto_tree_add_item (tlvtlv_tree, hf_docsis_optreq_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", type);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static void
dissect_optreq_tlv (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
  proto_item *it, *tlv_item, *tlv_len_item;
  proto_tree *tlv_tree, *tlvtlv_tree;
  unsigned pos = 0;
  unsigned length;
  uint8_t type;
  tvbuff_t *next_tvb;

  it = proto_tree_add_item(tree, hf_docsis_optreq_tlv_data, tvb, 0, tvb_reported_length(tvb), ENC_NA);
  tlv_tree = proto_item_add_subtree (it, ett_docsis_optreq_tlv);

  while (tvb_reported_length_remaining(tvb, pos) > 0)
  {
    type = tvb_get_uint8 (tvb, pos);
    length = tvb_get_uint8 (tvb, pos + 1);
    tlvtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, length + 2,
                                            ett_docsis_optreq_tlvtlv, &tlv_item,
                                            val_to_str(type, optreq_tlv_vals,
                                                       "Unknown TLV (%u)"));
    proto_tree_add_uint (tlvtlv_tree, hf_docsis_optreq_type, tvb, pos, 1, type);
    pos++;
    tlv_len_item = proto_tree_add_item (tlvtlv_tree, hf_docsis_optreq_length, tvb, pos, 1, ENC_NA);
    pos++;


    switch (type)
    {
    case OPT_REQ_REQ_STAT:
      if (length == 1)
      {

         static int * const req_stat[] = {
           &hf_docsis_optreq_reqstat_rxmer_stat_subc,
           &hf_docsis_optreq_reqstat_rxmer_subc_threshold_comp,
           &hf_docsis_optreq_reqstat_snr_marg_cand_prof,
           &hf_docsis_optreq_reqstat_codew_stat_cand_prof,
           &hf_docsis_optreq_reqstat_codew_thresh_comp_cand_prof,
           &hf_docsis_optreq_reqstat_ncp_field_stat,
           &hf_docsis_optreq_reqstat_ncp_crc_thresh_comp,
           &hf_docsis_optreq_reqstat_reserved,
           NULL
         };

         proto_tree_add_bitmask_list(tlvtlv_tree, tvb, pos, length, req_stat, ENC_BIG_ENDIAN);
      }
      else
      {
        expert_add_info_format(pinfo, tlv_len_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %u", length);
      }
      break;
    case OPT_REQ_RXMER_THRESH_PARAMS:
      next_tvb = tvb_new_subset_length(tvb, pos, length);
      dissect_optreq_tlv_rxmer_thresholding_parameters(next_tvb, pinfo, tlvtlv_tree);
      break;
    case OPT_REQ_TRIGGER_DEFINITION:
      next_tvb = tvb_new_subset_length(tvb, pos, length);
      dissect_optreq_tlv_trigger_definition(next_tvb, pinfo, tlvtlv_tree);
      break;
    default:
      proto_tree_add_item (tlvtlv_tree, hf_docsis_optreq_tlv_unknown, tvb, pos - 2, length+2, ENC_NA);
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", type);
      break;
    } /* switch */
    pos += length;
  } /* while */
}

static int
dissect_optreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *opt_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t downstream_channel_id, profile_identifier, opcode, id;

  it = proto_tree_add_item(tree, proto_docsis_optreq, tvb, 0, -1, ENC_NA);
  opt_tree = proto_item_add_subtree (it, ett_docsis_optreq);
  proto_tree_add_item (opt_tree, hf_docsis_optreq_reserved, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (opt_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint (opt_tree, hf_docsis_optreq_prof_id, tvb, 3, 1, ENC_BIG_ENDIAN, &profile_identifier);
  proto_tree_add_item_ret_uint (opt_tree, hf_docsis_optreq_opcode, tvb, 4, 1, ENC_BIG_ENDIAN, &opcode);

  col_add_fstr (pinfo->cinfo, COL_INFO, "OPT-REQ: DS CH ID: %u, Profile ID: %s (%u), Opcode: %s (%u)", downstream_channel_id,
                              val_to_str(profile_identifier, profile_id_vals, "Unknown Profile ID (%u)"), profile_identifier,
                              val_to_str(opcode, opt_opcode_vals, "Unknown Opcode (%u)"), opcode);

  id = (downstream_channel_id << 16) + profile_identifier;
  tlv_tvb = dissect_multipart(tvb, pinfo, opt_tree, data, MGT_OPT_REQ, id, 5);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_optreq_tlv(tlv_tvb, pinfo, opt_tree);
  return tvb_captured_length(tvb);
}

static void
dissect_optrsp_tlv_rxmer(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length, i;

  static int *const ect_rba_subband_direction[] = {
      &hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb0,
      &hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb1,
      &hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb2,
      NULL};

  while (pos + 2 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_ntohs(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_optrsp_rxmer_tlv, tvb, pos, tlv_length + 3, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, optrsp_rxmer_vals, "Unknown TLV %u"));
    if (tlv_type == OPT_RSP_RXMER_SUBCARRIER) // huge list
      tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_optrsp_rxmer_subcarrier_tlv);
    else
      tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_optrsp_rxmer_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_rxmer_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_rxmer_tlv_length, tvb, pos + 1, 2, ENC_BIG_ENDIAN);
    pos += 3;

    switch (tlv_type)
    {
    case OPT_RSP_RXMER_SUBCARRIER:
      for (i = 0; i < tlv_length; ++i)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_rxmer_subcarrier, tvb, pos + i, 1, ENC_BIG_ENDIAN);
      break;
    case OPT_RSP_RXMER_SUBCARRIER_THRESHOLD:
      proto_tree_add_item(tlv_tree, hf_docsis_optrsp_rxmer_subcarrier_threshold, tvb, pos, tlv_length, ENC_NA);
      break;
    case OPT_RSP_RXMER_SUBCARRIER_THRESHOLD_COUNT:
      if (tlv_length == 2)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_rxmer_subcarrier_threshold_count, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_RXMER_SNR_MARGIN:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_rxmer_snr_margin, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_RXMER_AVG:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_rxmer_avg, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_RXMER_ECT_RBA_SUBBAND_DIRECTION:
      if (tlv_length == 1) {
        proto_tree_add_bitmask_with_flags(tlv_tree, tvb, pos, hf_docsis_optrsp_rxmer_ect_rba_subband_direction,
                                          ett_docsis_optrsp_rxmer_tlv, ect_rba_subband_direction, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        proto_tree_add_bitmask_list(tlv_tree, tvb, pos, tlv_length, ect_rba_subband_direction, ENC_BIG_ENDIAN);
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_optrsp_tlv_data_cw(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  while (pos + 2 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_ntohs(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_optrsp_data_cw_tlv, tvb, pos, tlv_length + 3, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, optrsp_data_cw_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_optrsp_data_cw_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_data_cw_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_data_cw_tlv_length, tvb, pos + 1, 2, ENC_BIG_ENDIAN);
    pos += 3;

    switch (tlv_type)
    {
    case OPT_RSP_DATA_CW_COUNT:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_data_cw_count, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_DATA_CW_CORRECTED:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_data_cw_corrected, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_DATA_CW_UNCORRECTABLE:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_data_cw_uncorrectable, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_DATA_CW_THRESHOLD_COMPARISON:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_data_cw_threshold_comparison, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_optrsp_tlv_ncp_fields(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  while (pos + 2 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_ntohs(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_optrsp_ncp_fields_tlv, tvb, pos, tlv_length + 3, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, optrsp_ncp_fields_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_optrsp_ncp_fields_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_ncp_fields_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_ncp_fields_tlv_length, tvb, pos + 1, 2, ENC_BIG_ENDIAN);
    pos += 3;

    switch (tlv_type)
    {
    case OPT_RSP_NCP_FIELDS_COUNT:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_ncp_fields_count, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_NCP_FIELDS_FAILURE:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_ncp_fields_failure, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case OPT_RSP_NCP_FIELDS_THRESHOLD_COMPARISON:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_optrsp_ncp_fields_threshold_comparison, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_optrsp_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  while (pos + 2 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_ntohs(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_optrsp_tlv, tvb, pos, tlv_length + 3, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, optrsp_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_optrsp_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_optrsp_tlv_length, tvb, pos + 1, 2, ENC_BIG_ENDIAN);
    pos += 3;

    switch (tlv_type)
    {
    case OPT_RSP_RXMER:
      dissect_optrsp_tlv_rxmer(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    case OPT_RSP_DATA_CW:
      dissect_optrsp_tlv_data_cw(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    case OPT_RSP_NCP_FIELDS:
      dissect_optrsp_tlv_ncp_fields(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static int
dissect_optrsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *opt_item;
  proto_tree *opt_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t downstream_channel_id, profile_identifier, status, id;

  opt_item = proto_tree_add_item(tree, proto_docsis_optrsp, tvb, 0, -1, ENC_NA);
  opt_tree = proto_item_add_subtree(opt_item, ett_docsis_optrsp);
  proto_tree_add_item(opt_tree, hf_docsis_optrsp_reserved, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint(opt_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint(opt_tree, hf_docsis_optrsp_prof_id, tvb, 3, 1, ENC_BIG_ENDIAN, &profile_identifier);
  proto_tree_add_item_ret_uint(opt_tree, hf_docsis_optrsp_status, tvb, 4, 1, ENC_BIG_ENDIAN, &status);

  col_add_fstr(pinfo->cinfo, COL_INFO, "OPT-RSP: DS CH ID: %u, Profile ID: %s (%u), Status: %s (%u)", downstream_channel_id,
               val_to_str(profile_identifier, profile_id_vals, "Unknown Profile ID (%u)"), profile_identifier,
               val_to_str(status, opt_status_vals, "Unknown status (%u)"), status);

  id = (downstream_channel_id << 16) + profile_identifier;
  tlv_tvb = dissect_multipart(tvb, pinfo, opt_tree, data, MGT_OPT_RSP, id, 5);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_optrsp_tlv(tlv_tvb, pinfo, opt_item, opt_tree, 0, tvb_reported_length(tlv_tvb));
  return tvb_captured_length(tvb);
}

static int
dissect_optack (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *opt_tree;

  uint32_t downstream_channel_id, profile_identifier;

  it = proto_tree_add_item(tree, proto_docsis_optack, tvb, 0, -1, ENC_NA);
  opt_tree = proto_item_add_subtree (it, ett_docsis_optack);
  proto_tree_add_item (opt_tree, hf_docsis_optack_reserved, tvb, 0, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (opt_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint (opt_tree, hf_docsis_optack_prof_id, tvb, 3, 1, ENC_BIG_ENDIAN, &profile_identifier);

  col_add_fstr (pinfo->cinfo, COL_INFO, "OPT-ACK: DS CH ID: %u, Profile ID: %s (%u)", downstream_channel_id,
                              val_to_str(profile_identifier, profile_id_vals, "Unknown Profile ID (%u)"), profile_identifier);

  return tvb_captured_length(tvb);
}

static int
dissect_rba (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it, *rba_direction_it;
  proto_tree *rba_tree;

  uint32_t tg_id, dcid;
  uint32_t subband_index, nr_of_subbands;

  static int * const rba_control_byte[] = {
    &hf_docsis_rba_resource_block_change_bit,
    &hf_docsis_rba_expiration_time_valid_bit,
    &hf_docsis_rba_control_byte_bitmask_rsvd,
    NULL
  };

  it = proto_tree_add_item(tree, proto_docsis_rba, tvb, 0, -1, ENC_NA);
  rba_tree = proto_item_add_subtree (it, ett_docsis_rba);
  proto_tree_add_item_ret_uint (rba_tree, hf_docsis_rba_tg_id, tvb, 0, 1, ENC_BIG_ENDIAN, &tg_id);
  proto_tree_add_item (rba_tree, hf_docsis_rba_ccc, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (rba_tree, hf_docsis_rba_dcid, tvb, 2, 1, ENC_BIG_ENDIAN, &dcid);
  proto_tree_add_bitmask (rba_tree, tvb, 3, hf_docsis_rba_control_byte_bitmask, ett_docsis_rba_control_byte, rba_control_byte, ENC_BIG_ENDIAN);
  proto_tree_add_item (rba_tree, hf_docsis_rba_rba_time, tvb, 4, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item (rba_tree, hf_docsis_rba_rba_expiration_time, tvb, 8, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint (rba_tree, hf_docsis_rba_number_of_subbands, tvb, 12, 1, ENC_BIG_ENDIAN, &nr_of_subbands);
  for (subband_index =0; subband_index < nr_of_subbands; ++subband_index) {
      rba_direction_it = proto_tree_add_item (rba_tree, hf_docsis_rba_subband_direction, tvb, 13 + subband_index, 1, ENC_BIG_ENDIAN);
      proto_item_prepend_text(rba_direction_it, "Sub-band %d: ", subband_index);
  }

  col_add_fstr (pinfo->cinfo, COL_INFO, "RBA: TG_ID: %u, DCID: %u", tg_id, dcid);

  return tvb_captured_length(tvb);
}

static void
dissect_cwt_us_encodings_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree, *subtlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length, i;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_cwt_us_encodings_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, cwt_us_encodings_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_cwt_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_cwt_us_encodings_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_cwt_us_encodings_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case CWT_US_ENCODINGS_CID:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_cwt_us_encodings_cid, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CWT_US_ENCODINGS_SC_INDEX:
      subtlv_tree = proto_tree_add_subtree(tlv_tree, tvb, pos, length, ett_docsis_cwt_subtlv, NULL,
                                           "Upstream Subcarrier Indices");
      for (i = 0; i + 1 < tlv_length; i += 2)
        proto_tree_add_item(subtlv_tree, hf_docsis_cwt_us_encodings_sc_index, tvb, pos + i, 2, ENC_BIG_ENDIAN);
      if (i != tlv_length)
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CWT_US_ENCODINGS_POWER_BOOST:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_cwt_us_encodings_power_boost, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_cwt_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  uint32_t value;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_cwt_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, cwt_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_cwt_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_cwt_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_cwt_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case CWT_PHASE_ROTATION:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_cwt_phase_rotation, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CWT_MAX_DURATION:
      if (tlv_length == 2) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_cwt_max_duration, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 1000)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_cwt_out_of_range, "Invalid CWT Maximum Duration: %i", value);
      } else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case CWT_US_ENCODINGS:
      dissect_cwt_us_encodings_tlv(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static int
dissect_cwt_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *cwt_req_item;
  proto_tree *cwt_req_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t transaction_id, sub_band_id, op_code, id = 0;

  cwt_req_item = proto_tree_add_item(tree, proto_docsis_cwt_req, tvb, 0, -1, ENC_NA);
  cwt_req_tree = proto_item_add_subtree(cwt_req_item, ett_docsis_cwt_req);
  proto_tree_add_item_ret_uint(cwt_req_tree, hf_docsis_cwt_trans_id, tvb, 0, 1, ENC_BIG_ENDIAN, &transaction_id);
  proto_tree_add_item_ret_uint(cwt_req_tree, hf_docsis_cwt_sub_band_id, tvb, 1, 1, ENC_BIG_ENDIAN, &sub_band_id);
  proto_tree_add_item_ret_uint(cwt_req_tree, hf_docsis_cwt_op_code, tvb, 2, 1, ENC_BIG_ENDIAN, &op_code);

  col_add_fstr(pinfo->cinfo, COL_INFO, "CWT-REQ %s ID %u on sub-band %u",
               val_to_str(op_code, cwt_op_code_vals, "Unknown Op Code (%u)"),
               transaction_id, sub_band_id);

  id = (transaction_id << 8) + sub_band_id;
  tlv_tvb = dissect_multipart(tvb, pinfo, cwt_req_tree, data, MGT_CWT_REQ, id, 3);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_cwt_tlv(tlv_tvb, pinfo, cwt_req_item, cwt_req_tree, 0, tvb_reported_length(tlv_tvb));
  return tvb_captured_length(tvb);
}

static int
dissect_cwt_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *cwt_rsp_item;
  proto_tree *cwt_rsp_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t transaction_id, sub_band_id, op_code, status, id = 0;

  cwt_rsp_item = proto_tree_add_item(tree, proto_docsis_cwt_rsp, tvb, 0, -1, ENC_NA);
  cwt_rsp_tree = proto_item_add_subtree(cwt_rsp_item, ett_docsis_cwt_rsp);
  proto_tree_add_item_ret_uint(cwt_rsp_tree, hf_docsis_cwt_trans_id, tvb, 0, 1, ENC_BIG_ENDIAN, &transaction_id);
  proto_tree_add_item_ret_uint(cwt_rsp_tree, hf_docsis_cwt_sub_band_id, tvb, 1, 1, ENC_BIG_ENDIAN, &sub_band_id);
  proto_tree_add_item_ret_uint(cwt_rsp_tree, hf_docsis_cwt_op_code, tvb, 2, 1, ENC_BIG_ENDIAN, &op_code);
  proto_tree_add_item_ret_uint(cwt_rsp_tree, hf_docsis_cwt_status, tvb, 3, 1, ENC_BIG_ENDIAN, &status);

  col_add_fstr(pinfo->cinfo, COL_INFO, "CWT-RSP %s ID %u on sub-band %u: %s",
               val_to_str(op_code, cwt_op_code_vals, "Unknown Op Code (%u)"),
               transaction_id, sub_band_id,
               val_to_str(op_code, cwt_status_vals, "Unknown Status (%u)"));

  id = (transaction_id << 8) + sub_band_id;
  tlv_tvb = dissect_multipart(tvb, pinfo, cwt_rsp_tree, data, MGT_CWT_RSP, id, 4);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_cwt_tlv(tlv_tvb, pinfo, cwt_rsp_item, cwt_rsp_tree, 0, tvb_reported_length(tlv_tvb));
  return tvb_captured_length(tvb);
}

static void
dissect_ect_control_partial_service_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length, i;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_ect_control_partial_service_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, ect_control_partial_service_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_ect_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_partial_service_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_partial_service_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case ECT_CONTROL_PARTIAL_SERVICE_DCID:
      for (i = 0; i < tlv_length; ++i)
        proto_tree_add_item(tlv_tree, hf_docsis_ect_control_partial_service_dcid, tvb, pos + i, 1, ENC_BIG_ENDIAN);
      break;
    case ECT_CONTROL_PARTIAL_SERVICE_UCID:
      for (i = 0; i < tlv_length; ++i)
        proto_tree_add_item(tlv_tree, hf_docsis_ect_control_partial_service_ucid, tvb, pos + i, 1, ENC_BIG_ENDIAN);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_ect_control_method_bg_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  uint32_t value;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_ect_control_method_bg_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, ect_control_method_bg_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_ect_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_bg_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_bg_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case ECT_CONTROL_METHOD_BG_DURATION:
      if (tlv_length == 2) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_ect_control_method_bg_duration, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 1000)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_ect_control_out_of_range, "Invalid ECT Background Duration: %i", value);
      }
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_METHOD_BG_PERIODICITY:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_ect_control_method_bg_periodicity, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 30)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_ect_control_out_of_range, "Invalid ECT Background Periodicity: %i", value);
      }
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_METHOD_BG_EXPIRATION_TIME:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_ect_control_method_bg_expiration_time, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 255)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_ect_control_out_of_range, "Invalid ECT Background Expiration Time: %i", value);
      }
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_METHOD_BG_START_TIME:
      if (tlv_length == 4)
        proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_bg_start_time, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_ect_control_method_fg_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  uint32_t value;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_ect_control_method_fg_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, ect_control_method_fg_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_ect_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_fg_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_fg_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case ECT_CONTROL_METHOD_FG_DURATION:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_ect_control_method_fg_duration, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 128)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_ect_control_out_of_range, "Invalid ECT Foreground Duration: %i", value);
      }
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_METHOD_FG_PERIODICITY:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_ect_control_method_fg_periodicity, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 30)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_ect_control_out_of_range, "Invalid ECT Foreground Periodicity: %i", value);
      }
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_METHOD_FG_EXPIRATION_TIME:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_ect_control_method_fg_expiration_time, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 255)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_ect_control_out_of_range, "Invalid ECT Foreground Expiration Time: %i", value);
      }
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_METHOD_FG_DS_ZBL:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_fg_ds_zbl, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_ect_control_method_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_ect_control_method_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, ect_control_method_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_ect_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_method_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case ECT_CONTROL_METHOD_FG:
      dissect_ect_control_method_fg_tlv(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    case ECT_CONTROL_METHOD_BG:
      dissect_ect_control_method_bg_tlv(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_ect_control_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length, i;

  uint32_t value;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_ect_control_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, ect_control_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_ect_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_control_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case ECT_CONTROL_SUBBAND_DIRECTION:
      for (i = 0; i < tlv_length; ++i)
        proto_tree_add_item(tlv_tree, hf_docsis_ect_control_subband_direction, tvb, pos + i, 1, ENC_BIG_ENDIAN);
      break;
    case ECT_CONTROL_STATUS:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_ect_control_status, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_METHOD:
      dissect_ect_control_method_tlv(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    case ECT_CONTROL_PARTIAL_SERVICE:
      dissect_ect_control_partial_service_tlv(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    case ECT_CONTROL_DEFERRAL_TIME:
      if (tlv_length == 1)
        proto_tree_add_item(tlv_tree, hf_docsis_ect_control_deferral_time, tvb, pos, tlv_length, ENC_BIG_ENDIAN);
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    case ECT_CONTROL_RXMER_DURATION:
      if (tlv_length == 1) {
        proto_tree_add_item_ret_uint(tlv_tree, hf_docsis_ect_control_rxmer_duration, tvb, pos, tlv_length, ENC_BIG_ENDIAN, &value);
        if (value < 1 || value > 128)
          expert_add_info_format(pinfo, tlv_item, &ei_docsis_ect_control_out_of_range, "Invalid RxMER Duration: %i symbols", value);
      }
      else
        expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static void
dissect_ect_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_item *item, proto_tree *tree, int pos, int length)
{
  proto_item *tlv_item;
  proto_tree *tlv_tree;
  uint32_t tlv_type;
  int tlv_length, end = pos + length;

  while (pos + 1 < end)
  {
    tlv_type = tvb_get_uint8(tvb, pos);
    tlv_length = tvb_get_uint8(tvb, pos + 1);
    tlv_item = proto_tree_add_item(tree, hf_docsis_ect_tlv, tvb, pos, tlv_length + 2, ENC_NA);
    proto_item_set_text(tlv_item, "%s", val_to_str(tlv_type, ect_tlv_vals, "Unknown TLV %u"));
    tlv_tree = proto_item_add_subtree(tlv_item, ett_docsis_ect_tlv);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_tlv_type, tvb, pos, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_docsis_ect_tlv_length, tvb, pos + 1, 1, ENC_BIG_ENDIAN);
    pos += 2;

    switch (tlv_type)
    {
    case ECT_CONTROL:
      dissect_ect_control_tlv(tvb, pinfo, tlv_item, tlv_tree, pos, tlv_length);
      break;
    default:
      expert_add_info_format(pinfo, tlv_item, &ei_docsis_mgmt_tlvtype_unknown, "Unknown TLV type: %u", tlv_type);
      break;
    }
    pos += tlv_length;
  }
  if (pos != end)
    expert_add_info_format(pinfo, item, &ei_docsis_mgmt_tlvlen_bad, "Wrong TLV length: %i", length);
}

static int
dissect_ect_req(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ect_req_item;
  proto_tree *ect_req_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t transaction_id;

  ect_req_item = proto_tree_add_item(tree, proto_docsis_ect_req, tvb, 0, -1, ENC_NA);
  ect_req_tree = proto_item_add_subtree(ect_req_item, ett_docsis_ect_req);
  proto_tree_add_item_ret_uint(ect_req_tree, hf_docsis_ect_trans_id, tvb, 0, 2, ENC_BIG_ENDIAN, &transaction_id);

  col_add_fstr(pinfo->cinfo, COL_INFO, "ECT-REQ ID %u", transaction_id);

  tlv_tvb = dissect_multipart(tvb, pinfo, ect_req_tree, data, MGT_ECT_REQ, transaction_id, 2);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_ect_tlv(tlv_tvb, pinfo, ect_req_item, ect_req_tree, 0, tvb_reported_length(tlv_tvb));
  return tvb_captured_length(tvb);
}

static int
dissect_ect_rsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ect_rsp_item;
  proto_tree *ect_rsp_tree;
  tvbuff_t *tlv_tvb = NULL;

  uint32_t transaction_id, rsp_code;

  ect_rsp_item = proto_tree_add_item(tree, proto_docsis_ect_rsp, tvb, 0, -1, ENC_NA);
  ect_rsp_tree = proto_item_add_subtree(ect_rsp_item, ett_docsis_ect_rsp);
  proto_tree_add_item_ret_uint(ect_rsp_tree, hf_docsis_ect_trans_id, tvb, 0, 2, ENC_BIG_ENDIAN, &transaction_id);
  proto_tree_add_item_ret_uint(ect_rsp_tree, hf_docsis_ect_rsp_code, tvb, 2, 1, ENC_BIG_ENDIAN, &rsp_code);

  col_add_fstr(pinfo->cinfo, COL_INFO, "ECT-RSP ID %u: %s",
               transaction_id,
               val_to_str(rsp_code, ect_rsp_code_vals, "Unknown Response Code (%u)"));

  tlv_tvb = dissect_multipart(tvb, pinfo, ect_rsp_tree, data, MGT_ECT_RSP, transaction_id, 3);
  if (tlv_tvb != NULL && tvb_captured_length(tlv_tvb))
    dissect_ect_tlv(tlv_tvb, pinfo, ect_rsp_item, ect_rsp_tree, 0, tvb_reported_length(tlv_tvb));
  return tvb_captured_length(tvb);
}

static int
dissect_ext_rngreq (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data  _U_)
{
  proto_item *it;
  proto_tree *ext_rngreq_tree;

  uint32_t sid, downstream_channel_id, upstream_channel_id;

  it = proto_tree_add_item(tree, proto_docsis_ext_rngreq, tvb, 0, -1, ENC_NA);
  ext_rngreq_tree = proto_item_add_subtree (it, ett_docsis_ext_rngreq);
  proto_tree_add_item_ret_uint (ext_rngreq_tree, hf_docsis_rngreq_sid, tvb, 0, 2, ENC_BIG_ENDIAN, &sid);
  proto_tree_add_item_ret_uint (ext_rngreq_tree, hf_docsis_mgt_down_chid, tvb, 2, 1, ENC_BIG_ENDIAN, &downstream_channel_id);
  proto_tree_add_item_ret_uint (ext_rngreq_tree, hf_docsis_mgt_upstream_chid, tvb, 3, 1, ENC_BIG_ENDIAN, &upstream_channel_id);

  col_add_fstr (pinfo->cinfo, COL_INFO, "EXT-RNG-REQ: SID: %u, DS CH ID: %u, US CH ID: %u", sid, downstream_channel_id, upstream_channel_id);

  return tvb_captured_length(tvb);
}

static int
dissect_dpr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *dpr_item, *item;
  proto_tree *dpr_tree;

  uint32_t dcid, tg_id, duration;

  dpr_item = proto_tree_add_item(tree, proto_docsis_dpr, tvb, 0, -1, ENC_NA);
  dpr_tree = proto_item_add_subtree(dpr_item, ett_docsis_dpr);
  proto_tree_add_item(dpr_tree, hf_docsis_dpr_carrier, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint(dpr_tree, hf_docsis_dpr_dcid, tvb, 1, 1, ENC_BIG_ENDIAN, &dcid);
  proto_tree_add_item_ret_uint(dpr_tree, hf_docsis_dpr_tg_id, tvb, 2, 1, ENC_BIG_ENDIAN, &tg_id);
  proto_tree_add_item(dpr_tree, hf_docsis_dpr_reserved, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(dpr_tree, hf_docsis_dpr_start_time, tvb, 4, 4, ENC_BIG_ENDIAN);
  item = proto_tree_add_item_ret_uint(dpr_tree, hf_docsis_dpr_duration, tvb, 8, 4, ENC_BIG_ENDIAN, &duration);
  if ((duration & 0xff000000) > 0)
    expert_add_info_format(pinfo, item, &ei_docsis_dpr_out_of_range, "Invalid DPR Duration: %u", duration);

  col_add_fstr(pinfo->cinfo, COL_INFO, "DPR DCID %u on TG ID %u", dcid, tg_id);

  return tvb_captured_length(tvb);
}

static int
dissect_macmgmt (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void* data _U_)
{
  uint32_t type, version, dsap, ssap, msg_len;
  proto_item *mgt_hdr_it;
  proto_tree *mgt_hdr_tree;
  tvbuff_t *payload_tvb;
  uint8_t multipart;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "DOCSIS MGMT");

  col_clear(pinfo->cinfo, COL_INFO);

  set_address_tvb (&pinfo->dl_src, AT_ETHER, 6, tvb, 6);
  copy_address_shallow(&pinfo->src, &pinfo->dl_src);
  set_address_tvb (&pinfo->dl_dst, AT_ETHER, 6, tvb, 0);
  copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);

  static int * const multipart_field[] = {
    &hf_docsis_mgt_multipart_number_of_fragments,
    &hf_docsis_mgt_multipart_fragment_sequence_number,
    NULL
  };

  //We need version and type for decoding of ssap and dsap field: in case of RNG-REQ, these fields can contain the Transmit Power Level.
  version = tvb_get_uint8 (tvb, 17);
  type = tvb_get_uint8 (tvb, 18);
  dsap = tvb_get_uint8 (tvb, 14);
  ssap = tvb_get_uint8 (tvb, 15);

  mgt_hdr_it = proto_tree_add_item (tree, proto_docsis_mgmt, tvb, 0, 20, ENC_NA);
  mgt_hdr_tree = proto_item_add_subtree (mgt_hdr_it, ett_docsis_mgmt);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_dst_addr, tvb, 0, 6, ENC_NA);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_src_addr, tvb, 6, 6, ENC_NA);
  proto_tree_add_item_ret_uint (mgt_hdr_tree, hf_docsis_mgt_msg_len, tvb, 12, 2, ENC_BIG_ENDIAN, &msg_len);

  if ( ((type == MGT_RNG_REQ) || type == MGT_B_INIT_RNG_REQ)
       && version == 5
       && !(ssap==0 && dsap == 0) ) {
    //RNG_REQ or BONDED_INIT_RNG_REQ with upstream transmit power reporting, sent to 3.1 CMTS
    proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_31_transmit_power, tvb, 14, 2, ENC_BIG_ENDIAN);
  } else if (type == MGT_EXT_RNG_REQ) {
    //EXT_RNG_REQ with upstream transmit power reporting, sent to 4.0 CMTS
    proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_40_transmit_power, tvb, 14, 2, ENC_BIG_ENDIAN);
  } else if ( ((type == MGT_RNG_REQ && version == 1) || (type == MGT_B_INIT_RNG_REQ && version == 4))
       && ssap != 0 ) {
    //RNG_REQ or BONDED_INIT_RNG_REQ with upstream transmit power reporting, sent to 3.0 CMTS
    proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_dsap, tvb, 14, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_30_transmit_power, tvb, 15, 1, ENC_BIG_ENDIAN);
  } else {
    proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_dsap, tvb, 14, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_ssap, tvb, 15, 1, ENC_BIG_ENDIAN);
  }

  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_control, tvb, 16, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_version, tvb, 17, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_type, tvb, 18, 1, ENC_BIG_ENDIAN);

  p_add_proto_data(pinfo->pool, pinfo, proto_docsis_mgmt, KEY_MGMT_VERSION, GUINT_TO_POINTER(version));

  if (version < 5) {
    proto_tree_add_item (mgt_hdr_tree, hf_docsis_mgt_rsvd, tvb, 19, 1, ENC_BIG_ENDIAN);
  } else {
    proto_tree_add_bitmask(mgt_hdr_tree, tvb, 19, hf_docsis_mgt_multipart, ett_sub_tlv, multipart_field, ENC_BIG_ENDIAN);
    multipart = tvb_get_uint8 (tvb, 19);
    p_add_proto_data(pinfo->pool, pinfo, proto_docsis_mgmt, KEY_MGMT_MULTIPART, GUINT_TO_POINTER(multipart));
  }

  /* Code to Call subdissector */
  /* sub-dissectors are based on the type field */
  payload_tvb = tvb_new_subset_length (tvb, 20, msg_len - 6);

  /* Special case: map needs version. Two types of MAPs exist, with some difference in encoding: MAPv1 and MAPv5. See also DOCSIS3.1 MULPI spec */
  if (type == MGT_MAP) {
    if (!dissector_try_uint(docsis_mgmt_dissector_table, 256*version + type, payload_tvb, pinfo, tree)) {
      call_data_dissector(payload_tvb, pinfo, tree);
    }
  } else {
    if (!dissector_try_uint(docsis_mgmt_dissector_table, type, payload_tvb, pinfo, tree)) {
      call_data_dissector(payload_tvb, pinfo, tree);
    }
  }

  return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_docsis_mgmt (void)
{
  static hf_register_info hf[] = {
      /* Sync Message */
    {&hf_docsis_sync_cmts_timestamp,
     {"CMTS Timestamp", "docsis_sync.cmts_timestamp",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Sync CMTS Timestamp", HFILL}
    },
    /* UCD */
    {&hf_docsis_ucd_config_ch_cnt,
     {"Config Change Count", "docsis_ucd.confcngcnt",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Configuration Change Count", HFILL}
    },
    {&hf_docsis_ucd_mini_slot_size,
     {"Mini Slot Size (6.25us TimeTicks)", "docsis_ucd.mslotsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_type,
     {"Type", "docsis_ucd.type",
      FT_UINT8, BASE_DEC, VALS(channel_tlv_vals), 0x0,
      "Channel TLV type", HFILL}
    },
    {&hf_docsis_ucd_length,
     {"Length", "docsis_ucd.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Channel TLV length", HFILL}
    },
    {&hf_docsis_ucd_burst_type,
     {"Type", "docsis_ucd.burst.tlvtype",
      FT_UINT8, BASE_DEC, VALS(burst_tlv_vals), 0x0,
      "Burst TLV type", HFILL}
    },
    {&hf_docsis_ucd_burst_length,
     {"Length", "docsis_ucd.burst.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Burst TLV length", HFILL}
    },
    {&hf_docsis_ucd_symbol_rate,
     {"Symbol Rate (ksym/sec)", "docsis_ucd.symrate",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_frequency,
     {"Frequency (Hz)", "docsis_ucd.freq",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Upstream Center Frequency", HFILL}
    },
    {&hf_docsis_ucd_preamble_pat,
     {"Preamble Pattern", "docsis_ucd.preamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Preamble Superstring", HFILL}
    },
    {&hf_docsis_ucd_ext_preamble_pat,
     {"Extended Preamble Pattern", "docsis_ucd.extpreamble",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Extended Preamble Superstring", HFILL}
    },
    {&hf_docsis_ucd_scdma_mode_enabled,
     {"S-CDMA Mode Enabled", "docsis_ucd.scdma",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_spreading_interval,
     {"SCDMA Spreading Interval", "docsis_ucd.scdmaspreadinginterval",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_codes_per_mini_slot,
     {"SCDMA Codes per mini slot", "docsis_ucd.scdmacodesperminislot",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_active_codes,
     {"SCDMA Active Codes", "docsis_ucd.scdmaactivecodes",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_code_hopping_seed,
     {"SCDMA Code Hopping Seed", "docsis_ucd.scdmacodehoppingseed",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_us_ratio_num,
     {"SCDMA US Ratio Numerator", "docsis_ucd.scdmausrationum",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_us_ratio_denom,
     {"SCDMA US Ratio Denominator", "docsis_ucd.scdmausratiodenom",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_timestamp_snapshot,
     {"SCDMA Timestamp Snapshot", "docsis_ucd.scdmatimestamp",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_maintain_power_spectral_density,
     {"Maintain Power Spectral Density", "docsis_ucd.maintpower",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ranging_required,
     {"Ranging Required", "docsis_ucd.rangingreq",
      FT_UINT8, BASE_DEC, VALS (ranging_req_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_max_scheduled_codes,
     {"S-CDMA Max Scheduled Codes", "docsis_ucd.scdmamaxcodes",
      FT_UINT8, BASE_DEC, VALS (max_scheduled_codes_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_cm,
     {"Ranging Hold-Off (CM)","docsis_ucd.rnghoffcm",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_erouter,
     {"Ranging Hold-Off (eRouter)",
      "docsis_ucd.rnghofferouter",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_emta,
     {"Ranging Hold-Off (eMTA or EDVA)",
      "docsis_ucd.rnghoffemta",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_estb,
     {"Ranging Hold-Off (DSG/eSTB)",
      "docsis_ucd.rnghoffestb",
      FT_BOOLEAN, 32, TFS(&tfs_allow_inhibit), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_rsvd,
     {"Reserved",
      "docsis_ucd.rnghoffrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rnghoff_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_ucd.rngidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_cm,
     {"Channel Class ID (CM)","docsis_ucd.classidcm",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_erouter,
     {"Channel Class ID (eRouter)",
      "docsis_ucd.classiderouter",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x2,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_emta,
     {"Channel Class ID (eMTA or EDVA)",
      "docsis_ucd.classidemta",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x4,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_estb,
     {"Channel Class ID (DSG/eSTB)",
      "docsis_ucd.classidestb",
      FT_UINT32, BASE_DEC, VALS (inhibit_allow_vals), 0x8,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_rsvd,
     {"Reserved",
      "docsis_ucd.classidrsvd",
      FT_UINT32, BASE_HEX, NULL, 0xFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_chan_class_id_id_ext,
     {"CM Ranging Class ID Extension",
      "docsis_ucd.classidext",
      FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_subc_excl_band,
     {"UCD Change Indicator Bitmask: Subcarrier Exclusion Band TLV", "docsis_ucd.burst.ucd_change_ind_bitmask_subc_excl_band",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_unused_subc,
     {"UCD Change Indicator Bitmask: Unused Subcarrier Specification TLV", "docsis_ucd.burst.ucd_change_ind_bitmask_unused_subc",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_other_subc,
     {"UCD Change Indicator Bitmask: Other than Subcarrier Exclusion Band and Unused Subcarrier Specification TLV", "docsis_ucd.burst.ucd_change_ind_bitmask_other_subc",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc5,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC5", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc5",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x08,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc6,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC6", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc6",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x10,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc9,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC9", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc9",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x20,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc10,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC10", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc10",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x40,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc11,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC11", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc11",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x80,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc12,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC12", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc12",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x01,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc13,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC13", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc13",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x02,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_burst_attr_iuc3_or_4,
     {"UCD Change Indicator Bitmask: Burst Attributes associated with IUC3 or IUC4", "docsis_ucd.burst.ucd_change_ind_bitmask_burst_attr_iuc3_or_4",
      FT_BOOLEAN, 8, TFS(&tfs_ucd_change_ind_vals), 0x04,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_change_ind_bitmask_reserved,
     {"UCD Change Indicator Bitmask: Reserved", "docsis_ucd.burst.ucd_change_ind_bitmask_reserved",
      FT_UINT8, BASE_HEX, NULL, 0xF8,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_timestamp_snapshot,
     {"OFDMA Timestamp Snapshot", "docsis_ucd.ofdma_timestamp_snapshot",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_timestamp_snapshot_reserved,
     {"OFDMA Timestamp Snapshot - Reserved", "docsis_ucd.ofdma_timestamp_snapshot_reserved",
      FT_UINT40, BASE_HEX, NULL, 0xF000000000,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_timestamp_snapshot_d30timestamp,
     {"OFDMA Timestamp Snapshot - D3.0 timestamp", "docsis_ucd.ofdma_timestamp_snapshot_d30timestamp",
      FT_UINT40, BASE_HEX, NULL, 0x0FFFFFFFF0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_timestamp_snapshot_4msbits_of_div20,
     {"OFDMA Timestamp Snapshot - 4 Most Significant bits of div20 field", "docsis_ucd.ofdma_timestamp_snapshot_4msbits_of_div20",
      FT_UINT40, BASE_HEX, NULL, 0x000000000F,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_timestamp_snapshot_minislot_count,
     {"OFDMA Timestamp Snapshot - Minislot Count", "docsis_ucd.ofdma_timestamp_snapshot_minislot_count",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_cyclic_prefix_size,
     {"OFDMA Cyclic Prefix Size", "docsis_ucd.ofdma_cyclic_prefix_size",
      FT_UINT8, BASE_DEC, VALS(ofdma_cyclic_prefix_size_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_ofdma_rolloff_period_size,
     {"OFDMA Rolloff Period Size", "docsis_ucd.ofdma_rolloff_period_size",
      FT_UINT8, BASE_DEC, VALS(ofdma_rolloff_period_size_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_subc_spacing,
     {"Subcarrier Spacing", "docsis_ucd.subc_spacing",
      FT_UINT8, BASE_DEC, VALS(subc_spacing_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_cent_freq_subc0,
     {"Center Frequency of Subcarrier 0", "docsis_ucd.cent_freq_subc0",
      FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_hz), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_subcarrier_range,
     {"Subcarrier range", "docsis_ucd.subc_range",
      FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_symb_ofdma_frame,
     {"Symbols in OFDMA frame", "docsis_ucd.symb_ofdma_frame",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_rand_seed,
     {"Randomization Seed", "docsis_ucd.rand_seed",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_extended_us_channel,
     {"Extended Upstream Channel", "docsis_ucd.extended_us_channel",
      FT_UINT8, BASE_DEC, VALS (extended_us_channel_vals), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_iuc,
     {"Interval Usage Code", "docsis_ucd.iuc",
      FT_UINT8, BASE_DEC, VALS (iuc_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_mod_type,
     {"Modulation Type", "docsis_ucd.burst.modtype",
      FT_UINT8, BASE_DEC, VALS (mod_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_diff_encoding,
     {"Differential Encoding", "docsis_ucd.burst.diffenc",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_len,
     {"Preamble Length (Bits)", "docsis_ucd.burst.preamble_len",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_preamble_val_off,
     {"Preamble Offset (Bits)", "docsis_ucd.burst.preamble_off",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_fec,
     {"FEC (T)", "docsis_ucd.burst.fec",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "FEC (T) Codeword Parity Bits = 2^T", HFILL}
    },
    {&hf_docsis_burst_fec_codeword,
     {"FEC Codeword Info bytes (k)", "docsis_ucd.burst.fec_codeword",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_seed,
     {"Scrambler Seed", "docsis_ucd.burst.scrambler_seed",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      "Burst Descriptor", HFILL}
    },
    {&hf_docsis_burst_max_burst,
     {"Max Burst Size (Minislots)", "docsis_ucd.burst.maxburst",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_guard_time,
     {"Guard Time Size (Symbol Times)", "docsis_ucd.burst.guardtime",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_last_cw_len,
     {"Last Codeword Length", "docsis_ucd.burst.last_cw_len",
      FT_UINT8, BASE_DEC, VALS (last_cw_len_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_burst_scrambler_onoff,
     {"Scrambler On/Off", "docsis_ucd.burst.scrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rs_int_depth,
     {"RS Interleaver Depth", "docsis_ucd.burst.rsintdepth",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Depth", HFILL}
    },
    {&hf_docsis_rs_int_block,
     {"RS Interleaver Block Size", "docsis_ucd.burst.rsintblock",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "R-S Interleaver Block", HFILL}
    },
    {&hf_docsis_preamble_type,
     {"Preamble Type", "docsis_ucd.burst.preambletype",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_scrambler_onoff,
     {"Scrambler On/Off", "docsis_ucd.burst.scdmascrambleronoff",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      "SCDMA Scrambler On/Off", HFILL}
    },
    {&hf_docsis_ucd_scdma_codes_per_subframe,
     {"SCDMA Codes per Subframe", "docsis_ucd.burst.scdmacodespersubframe",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_framer_int_step_size,
     {"SCDMA Framer Interleaving Step Size", "docsis_ucd.burst.scdmaframerintstepsize",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_tcm_enabled,
     {"TCM Enabled", "docsis_ucd.burst.tcmenabled",
      FT_UINT8, BASE_DEC, VALS (on_off_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_active_code_hopping,
     {"S-CDMA Selection Mode for Active Codes and Code Hopping", "docsis_ucd.selectcodehop",
      FT_UINT8, BASE_DEC, VALS (tlv20_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_scdma_selection_active_codes,
     {"S-CDMA Selection String for Active Codes", "docsis_ucd.selectcode",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_higher_ucd_for_same_ucid,
     {"Higher UCD for the same UCID", "docsis_ucd.highucdpresent",
      FT_BOOLEAN, 8, TFS(&type35ucd_tfs_present_not_present), 0x1,
      NULL, HFILL}
    },
    {&hf_docsis_ucd_higher_ucd_for_same_ucid_resv,
     {"Reserved", "docsis_ucd.highucdresv",
      FT_UINT8, BASE_HEX, NULL, 0xFE,
      NULL, HFILL}
    },
    {&hf_docsis_subc_init_rang,
     {"Subcarriers (Nir) Initial Ranging", "docsis_ucd.burst.subc_init_rang",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_subc_fine_rang,
     {"Subcarriers (Nfr) Fine Ranging", "docsis_ucd.burst.subc_fine_rang",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_prof_mod_order,
     {"OFDMA Profile: modulation", "docsis_ucd.burst.ofma_prof_mod_order",
      FT_UINT8, BASE_DEC, VALS(ofdma_prof_mod_order), 0xF0,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_prof_pilot_pattern,
     {"OFDMA Profile: pilot pattern", "docsis_ucd.burst.ofma_prof_pilot_pattern",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_prof_num_add_minislots,
     {"OFDMA Profile: Additional Minislots that have identical bit-loading and pilot pattern index", "docsis_ucd.burst.ofma_prof_add_minislots",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_ir_pow_ctrl_start_pow,
     {"OFDMA IR Power Control Starting Power Level", "docsis_ucd.burst.ofma_ir_pow_ctrl_start_pow",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(ofdma_ir_pow_ctrl_start_pow), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_ofdma_ir_pow_ctrl_step_size,
     {"OFDMA IR Power Control Step Size", "docsis_ucd.burst.ofma_ir_pow_ctrl_step_size",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(ofdma_ir_pow_ctrl_step_size), 0x00,
      NULL, HFILL}
    },
    /* MAP */
    {&hf_docsis_map_ucd_count,
     {"UCD Count", "docsis_map.ucdcount",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Map UCD Count", HFILL}
    },
    {&hf_docsis_map_numie,
     {"Number of IE's", "docsis_map.numie",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of Information Elements", HFILL}
    },
    {&hf_docsis_map_numie_v5,
     {"Number of IE's", "docsis_map.numie",
      FT_UINT16, BASE_DEC, NULL, 0xFF80,
      "Number of Information Elements", HFILL}
    },
    {&hf_docsis_map_rsvd_v5,
     {"Reserved [0x00]", "docsis_map.rsvd",
      FT_UINT8, BASE_HEX, NULL, 0x70,
      "Reserved Byte", HFILL}
    },
    {&hf_docsis_map_cat,
     {"CAT", "docsis_map.cat",
      FT_UINT8, BASE_HEX, NULL, 0x0F,
      NULL, HFILL}
    },

    {&hf_docsis_map_alloc_start,
     {"Alloc Start Time (minislots)", "docsis_map.allocstart",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_ack_time,
     {"ACK Time (minislots)", "docsis_map.acktime",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_rng_start,
     {"Ranging Backoff Start", "docsis_map.rng_start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_rng_end,
     {"Ranging Backoff End", "docsis_map.rng_end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_data_start,
     {"Data Backoff Start", "docsis_map.data_start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_data_end,
     {"Data Backoff End", "docsis_map.data_end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_ie,
     {"Information Element", "docsis_map.ie",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_probe_ie,
     {"Probe Information Element", "docsis_map.probe_ie",
      FT_UINT32, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_map_rsvd,
     {"Reserved", "docsis_map.rsvd",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Reserved Byte", HFILL}
    },
    {&hf_docsis_map_sid,
     {"Service Identifier", "docsis_map.sid",
      FT_UINT32, BASE_DEC, NULL, 0xFFFC0000,
      NULL, HFILL}
    },
    {&hf_docsis_map_iuc,
     {"Interval Usage Code", "docsis_map.iuc",
      FT_UINT32, BASE_DEC, VALS(iuc_vals), 0x0003c000,
      NULL, HFILL}
    },
    {&hf_docsis_map_offset,
     {"Offset", "docsis_map.offset",
      FT_UINT32, BASE_DEC, NULL, 0x00003fff,
      NULL, HFILL}
    },
    {&hf_docsis_map_mer,
     {"MER (CMTS RxMER Measurement)", "docsis_map.mer",
      FT_BOOLEAN, 32, TFS(&tfs_on_off), 0x00020000,
      NULL, HFILL}
    },
    {&hf_docsis_map_pw,
     {"PW (Power)", "docsis_map.pw",
      FT_BOOLEAN, 32, TFS(&pw_vals), MAP_PROBE_IE_PW_MASK,
      NULL, HFILL}
    },
    {&hf_docsis_map_eq,
     {"EQ (Tx Equalization)", "docsis_map.eq",
      FT_BOOLEAN, 32, TFS(&tfs_disabled_enabled), 0x00008000,
      NULL, HFILL}
    },
    {&hf_docsis_map_st,
     {"St (Stagger)", "docsis_map.st",
      FT_BOOLEAN, 32, TFS(&tfs_yes_no), MAP_PROBE_IE_ST_MASK,
      NULL, HFILL}
    },
    {&hf_docsis_map_probe_frame,
     {"Probe Frame", "docsis_map.probe_frame",
      FT_UINT32, BASE_DEC, NULL, 0x00003000,
      NULL, HFILL}
    },
    {&hf_docsis_map_symbol_in_frame,
     {"Symbol in Frame", "docsis_map.symbol_in_frame",
      FT_UINT32, BASE_DEC, NULL, 0x00000fc0,
      NULL, HFILL}
    },
    {&hf_docsis_map_start_subc,
     {"Start Subc", "docsis_map.start_subc",
      FT_UINT32, BASE_DEC, NULL, 0x00000038,
      NULL, HFILL}
    },
    {&hf_docsis_map_subc_skip,
     {"Subc Skip", "docsis_map.subc_skip",
      FT_UINT32, BASE_DEC, NULL, 0x00000007,
      NULL, HFILL}
    },
    {&hf_docsis_map_ect,
     {"ECT Control", "docsis_map.ect",
      FT_UINT32, BASE_DEC, VALS(map_ect_vals), 0x00000007,
      NULL, HFILL}
    },

    /* RNG-REQ */
    {&hf_docsis_rngreq_sid_field_bit15,
     {"SID field bit 15", "docsis_rngreq.sid_field_bit15",
      FT_BOOLEAN, 8, TFS(&sid_field_bit15_tfs), 0x80,
      NULL, HFILL}
    },
    {&hf_docsis_rngreq_sid_field_bit14,
     {"SID field bit 14", "docsis_rngreq.sid_field_bit14",
      FT_BOOLEAN, 8, TFS(&sid_field_bit14_tfs), 0x40,
      NULL, HFILL}
    },
    {&hf_docsis_rngreq_sid_field_bit15_14,
     {"SID field bit 15 to 14", "docsis_rngreq.sid_field_bit15_14",
      FT_UINT8, BASE_HEX, VALS(sid_field_bit15_14_vals), 0xC0,
      NULL, HFILL}
    },
    {&hf_docsis_rngreq_sid,
     {"Service Identifier", "docsis_rngreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x3FFF,
      NULL, HFILL}
    },
    {&hf_docsis_rngreq_pend_compl,
     {"Pending Till Complete", "docsis_rngreq.pendcomp",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Upstream Channel ID", HFILL}
    },
    /* RNG-RSP */
    {&hf_docsis_rngrsp_type,
     {"Type", "docsis_rngrsp.type",
      FT_UINT8, BASE_DEC, VALS(rngrsp_tlv_vals), 0x0,
      "TLV Type", HFILL}
     },
    {&hf_docsis_rngrsp_length,
     {"Length", "docsis_rngrsp.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "TLV Length", HFILL}
     },
    {&hf_docsis_rngrsp_sid,
     {"Service Identifier", "docsis_rngrsp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_timing_adj,
     {"Timing Adjust (6.25us/64)", "docsis_rngrsp.timingadj",
      FT_INT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_power_adj,
     {"Power Level Adjust (0.25dB units)", "docsis_rngrsp.poweradj",
      FT_INT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_freq_adj,
     {"Offset Freq Adjust (Hz)", "docsis_rngrsp.freqadj",
      FT_INT16, BASE_DEC, NULL, 0x0,
      "Frequency Adjust", HFILL}
     },
    {&hf_docsis_rngrsp_xmit_eq_adj,
     {"Transmit Equalization Adjust", "docsis_rngrsp.xmit_eq_adj",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_ranging_status,
     {"Ranging Status", "docsis_rngrsp.rng_stat",
      FT_UINT8, BASE_DEC, VALS (rng_stat_vals), 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_down_freq_over,
     {"Downstream Frequency Override (Hz)", "docsis_rngrsp.freq_over",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_upstream_ch_over,
     {"Upstream Channel ID Override", "docsis_rngrsp.chid_override",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_xmit_eq_set,
     {"Transmit Equalization Set", "docsis_rngrsp.xmit_eq_set",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_rngrsp_rngrsp_t4_timeout_multiplier,
     {"Multiplier of the default T4 Timeout", "docsis_rngrsp.t4_timeout_multiplier",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "T4 Timeout Multiplier (the valid range is 1-10)", HFILL}
     },
    {&hf_docsis_rngrsp_dynamic_range_window_upper_edge,
     {"Dynamic Range Window Upper Edge", "docsis_rngrsp.dynamic_range_window_upper_edge",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Dynamic Range Window Upper EDGE (in units of 0.25 db below the max allowable setting)", HFILL}
     },
    {&hf_docsis_rngrsp_tlv_unknown,
     {"Unknown TLV", "docsis_rngrsp.tlv.unknown",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_main_tap_location,
      {"Main Tap Location", "docsis_rngrsp.tlv.trans_eq_enc_scdma_tdma.main_tap_location",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_number_of_forward_taps_per_symbol,
      {"Number of Forward Taps per Symbol", "docsis_rngrsp.tlv.trans_eq_enc_scdma_tdma.nr_of_forward_taps_per_symbol",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_number_of_forward_taps_n,
      {"Number of Forward Taps (N)", "docsis_rngrsp.tlv.trans_eq_enc_scdma_tdma.nr_of_forward_taps_n",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_scdma_tdma_reserved,
      {"Reserved", "docsis_rngrsp.tlv.trans_eq_enc_scdma_tdma.reserved",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_data,
     {"Transmit equalization data", "docsis_rngrsp.tlv.trans_eq_data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_lowest_subc,
     {"Lowest Subcarrier for this TLV", "docsis_rngrsp.tlv.trans_eq_enc_lowest_subc",
      FT_UINT24, BASE_DEC, NULL, 0xFFF000,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_highest_subc,
     {"Highest Subcarrier for this TLV", "docsis_rngrsp.tlv.trans_eq_enc_highest_subc",
      FT_UINT24, BASE_DEC, NULL, 0x0FFF,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_coef_real,
     {"Coefficient (real)", "docsis_rngrsp.tlv.trans_eq_enc_coef_real",
      FT_INT16, BASE_CUSTOM, CF_FUNC(two_compl_frac), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_trans_eq_enc_coef_imag,
     {"Coefficient (imag)", "docsis_rngrsp.tlv.trans_eq_enc_coef_imag",
      FT_INT16, BASE_CUSTOM, CF_FUNC(two_compl_frac), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_commanded_power_data,
     {"Commanded Power Data", "docsis_rngrsp.tlv.comm_pwr_data",
      FT_BYTES, BASE_NONE, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_commanded_power_dynamic_range_window,
     {"Dynamic Range Window", "docsis_rngrsp.tlv.comm_pwr_dyn_range_window",
      FT_INT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_commanded_power_ucid,
     {"UCID", "docsis_rngrsp.tlv.comm_pwr_ucid",
      FT_UINT8, BASE_DEC, NULL, 0x00,
      NULL, HFILL}
    },
    {&hf_docsis_rngrsp_commanded_power_trans_pow_lvl,
     {"Transmit Power Level (quarter dBmV)", "docsis_rngrsp.tlv.comm_pwr_trans_pow_lvl",
      FT_INT16, BASE_CUSTOM, CF_FUNC(fourth_db), 0x00,
      NULL, HFILL}
    },

     /* REG_REQ */
    {&hf_docsis_regreq_sid,
     {"Service Identifier", "docsis_regreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
     /* REG_RSP */
    {&hf_docsis_regrsp_sid,
     {"Service Identifier", "docsis_regrsp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_regrsp_response,
     {"Response Code", "docsis_regrsp.respnse",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* BPKM */
    {&hf_docsis_bpkm_code,
     {"Code", "docsis_bpkm.code",
      FT_UINT8, BASE_DEC, VALS (code_field_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkm_ident,
     {"Identifier", "docsis_bpkm.ident",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkm_length,
     {"Length", "docsis_bpkm.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr,
     {"Attributes", "docsis_bpkm.attr",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_tlv,
     {"TLV", "docsis_bpkm.attr.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_bpkmattr_tlv_type,
     {"Type", "docsis_bpkm.attr.tlv.type",
      FT_UINT8, BASE_DEC, VALS(bpkmattr_tlv_vals), 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_bpkmattr_tlv_length,
     {"Length", "docsis_bpkm.attr.tlv.length",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
     },
    {&hf_docsis_bpkmattr_serial_num,
     {"Serial Number", "docsis_bpkm.attr.serialnum",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_manf_id,
     {"Manufacturer ID", "docsis_bpkm.attr.manfid",
      FT_UINT24, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_mac_addr,
     {"MAC Address", "docsis_bpkm.attr.macaddr",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_rsa_pub_key,
     {"RSA Public Key", "docsis_bpkm.attr.rsa_pub_key",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded RSA Public Key", HFILL}
    },
    {&hf_docsis_bpkmattr_cm_id,
     {"CM Identification", "docsis_bpkm.attr.cmid",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_display_str,
     {"Display String", "docsis_bpkm.attr.dispstr",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_auth_key,
     {"Auth Key", "docsis_bpkm.attr.auth_key",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "Encrypted Authorization Key", HFILL}
    },
    {&hf_docsis_bpkmattr_tek,
     {"Traffic Encryption Key", "docsis_bpkm.attr.tek",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "Encrypted Traffic Encryption Key", HFILL}
    },
    {&hf_docsis_bpkmattr_key_life,
     {"Key Lifetime (s)", "docsis_bpkm.attr.keylife",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "Remaining key lifetime (s)", HFILL}
    },
    {&hf_docsis_bpkmattr_key_seq,
     {"Key Sequence Number", "docsis_bpkm.attr.keyseq",
      FT_UINT8, BASE_DEC, NULL, 0x0f,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_hmac_digest,
     {"HMAC Digest", "docsis_bpkm.attr.hmacdigest",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "HMAC Digest (160-bit keyed SHA-1 hash)", HFILL}
    },
    {&hf_docsis_bpkmattr_said,
     {"SAID", "docsis_bpkm.attr.said",
      FT_UINT16, BASE_DEC, NULL, 0x3fff,
      "Security Association ID", HFILL}
    },
    {&hf_docsis_bpkmattr_tek_params,
     {"TEK Parameters", "docsis_bpkm.attr.tekparams",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cbc_iv,
     {"CBC IV", "docsis_bpkm.attr.cbciv",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "Cypher Block Chaining initialization vector", HFILL}
    },
    {&hf_docsis_bpkmattr_error_code,
     {"Error Code", "docsis_bpkm.attr.errcode",
      FT_UINT8, BASE_DEC, VALS (error_code_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_ca_cert,
     {"Device CA Certificate", "docsis_bpkm.attr.cacert",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded Device CA Certificate", HFILL}
    },
    {&hf_docsis_bpkmattr_cm_cert,
     {"CM Certificate", "docsis_bpkm.attr.cmcert",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded CM Device Certificate", HFILL}
    },
    {&hf_docsis_bpkmattr_security_cap,
     {"Security Capabilities", "docsis_bpkm.attr.seccap",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_crypto_suite,
     {"Cryptographic Suite", "docsis_bpkm.attr.cryptosuite",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_crypto_suite_encr,
     {"Encryption", "docsis_bpkm.attr.cryptosuite.encr",
      FT_UINT16, BASE_HEX, VALS(bpkm_crypto_suite_encr_vals), 0xff00,
      "Data Encryption Algorithm", HFILL}
    },
    {&hf_docsis_bpkmattr_crypto_suite_auth,
     {"Authentication", "docsis_bpkm.attr.cryptosuite.auth",
      FT_UINT16, BASE_HEX, VALS(bpkm_crypto_suite_auth_vals), 0x00ff,
      "Data Authentication Algorithm", HFILL}
    },
    {&hf_docsis_bpkmattr_crypto_suite_list,
     {"Cryptographic Suite List", "docsis_bpkm.attr.crypto_suite_lst",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_bpi_version,
     {"BPI Version", "docsis_bpkm.attr.bpiver",
      FT_UINT8, BASE_DEC, VALS (bpi_ver_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_sa_descr,
     {"SA Descriptor", "docsis_bpkm.attr.sadescr",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "Security Association Descriptor", HFILL}
    },
    {&hf_docsis_bpkmattr_sa_type,
     {"SA Type", "docsis_bpkm.attr.satype",
      FT_UINT8, BASE_DEC, VALS(bpi_sa_vals), 0x0,
      "Security Association Type", HFILL}
    },
    {&hf_docsis_bpkmattr_sa_query,
     {"SA Query", "docsis_bpkm.attr.saquery",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "Security Association Query", HFILL}
    },
    {&hf_docsis_bpkmattr_sa_query_type,
     {"SA Query Type", "docsis_bpkm.attr.saquery_type",
      FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(bpi_sa_query_type_vals), 0x0,
      "Security Association Query Type", HFILL}
    },
    {&hf_docsis_bpkmattr_ip_address,
     {"IP Address", "docsis_bpkm.attr.ipaddr",
      FT_IPv4, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_download_param,
     {"Download Parameters", "docsis_bpkm.attr.dnld_params",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cvc_root_ca_cert,
     {"CVC Root CA Certificate (deprecated)", "docsis_bpkm.attr.cvc_root_ca_cert",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded CVC Root CA Certificate from the legacy PKI", HFILL}
    },
    {&hf_docsis_bpkmattr_cvc_ca_cert,
     {"CVC CA Certificate (deprecated)", "docsis_bpkm.attr.cvc_ca_cert",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded CVC CA Certificate from the legacy PKI", HFILL}
    },
    {&hf_docsis_bpkmattr_dev_ca_cert,
     {"Device CA Certificate", "docsis_bpkm.attr.dev_ca_cert",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded Device CA Certificate from the new PKI", HFILL}
    },
    {&hf_docsis_bpkmattr_root_ca_cert,
     {"Root CA Certificate", "docsis_bpkm.attr.root_ca_cert",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded Root CA Certificate from the new PKI", HFILL}
    },
    {&hf_docsis_bpkmattr_cm_nonce,
     {"CM Nonce", "docsis_bpkm.attr.cm_nonce",
      FT_UINT64, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_msg_signature,
     {"Message Signature", "docsis_bpkm.attr.msg_signature",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      "DER-encoded CMS Signature", HFILL}
    },
    {&hf_docsis_bpkmattr_key_exchange_share_field_id,
     {"Key Exchange Share: Field ID", "docsis_bpkm.attr.key_exchange_share.field_id",
      FT_UINT16, BASE_HEX, VALS(bpkmattr_key_exchange_share_field_id_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_key_exchange_share_key_share,
     {"Key Exchange Share", "docsis_bpkm.attr.key_exchange_share.key_share",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_allowed_bpi_versions,
     {"Allowed BPI Versions", "docsis_bpkm.attr.allowed_bpi_versions",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_allowed_bpi_version,
     {"BPI Version", "docsis_bpkm.attr.allowed_bpi_version",
      FT_UINT8, BASE_DEC, VALS(bpi_ver_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_ocsp_responses,
     {"OCSP Responses", "docsis_bpkm.attr.ocsp_responses",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_ocsp_response,
     {"OCSP Response", "docsis_bpkm.attr.ocsp_response",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation,
     {"CMTS Designation", "docsis_bpkm.attr.cmts_designation",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_data_type,
     {"DataType", "docsis_bpkm.attr.cmts_designation.data_type",
      FT_UINT8, BASE_DEC, VALS(bpkm_cmts_binding_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_certificate_fingerprint,
     {"Certificate Fingerprint", "docsis_bpkm.attr.cmts_designation.certificate_fingerprint",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_common_name,
     {"Common Name", "docsis_bpkm.attr.cmts_designation.common_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_org_unit,
     {"Organizational Unit", "docsis_bpkm.attr.cmts_designation.org_unit",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_org_name,
     {"Organization Name", "docsis_bpkm.attr.cmts_designation.org_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_serial_number,
     {"Serial Number", "docsis_bpkm.attr.cmts_designation.serial_number",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_issuing_ca_fingerprint,
     {"Issuing CA Fingerprint", "docsis_bpkm.attr.cmts_designation.issuing_ca_fingerprint",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_issuing_ca_common_name,
     {"Issuing CA Common Name", "docsis_bpkm.attr.cmts_designation.issuing_ca_common_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_issuing_ca_org_unit,
     {"Issuing CA Organizational Unit", "docsis_bpkm.attr.cmts_designation.issuing_ca_org_unit",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_issuing_ca_org_name,
     {"Issuing CA Organization Name", "docsis_bpkm.attr.cmts_designation.issuing_ca_org_name",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cmts_designation_issuing_ca_serial_number,
     {"Issuing CA Serial Number", "docsis_bpkm.attr.cmts_designation.issuing_ca_serial_number",
      FT_STRING, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_cm_status_code,
     {"CM-Status Code", "docsis_bpkm.attr.cm_status_code",
      FT_UINT8, BASE_DEC, VALS(bpkm_cm_status_code_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_detected_errors,
     {"Detected Errors", "docsis_bpkm.attr.detected_errors",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bpkmattr_vendor_def,
     {"Vendor Defined", "docsis_bpkm.attr.vendordef",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    /* REG-ACK */
    {&hf_docsis_regack_sid,
     {"Service Identifier", "docsis_regack.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_regack_response,
     {"Response Code", "docsis_regack.respnse",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DAS-RSP */
    {&hf_docsis_dsarsp_response,
     {"Confirmation Code", "docsis_dsarsp.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsaack_response,
     {"Confirmation Code", "docsis_dsaack.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DSC-RSP */
    {&hf_docsis_dscrsp_response,
     {"Confirmation Code", "docsis_dscrsp.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dscack_response,
     {"Confirmation Code", "docsis_dscack.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DSD-REQ */
    {&hf_docsis_dsdreq_rsvd,
     {"Reserved", "docsis_dsdreq.rsvd",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsdreq_sfid,
     {"Service Flow ID", "docsis_dsdreq.sfid",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* DSD-RSP */
    {&hf_docsis_dsdrsp_confcode,
     {"Confirmation Code", "docsis_dsdrsp.confcode",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dsdrsp_rsvd,
     {"Reserved", "docsis_dsdrsp.rsvd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* DCC-REQ */
    {&hf_docsis_dccreq_type,
     {
      "Type",
      "docsis_dccreq.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcc_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_length,
     {
      "Length",
      "docsis_dccreq.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_tran_id ,
     {
       "Transaction ID",
       "docsis_dccreq.tran_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_up_chan_id ,
     {
       "Up Channel ID",
       "docsis_dccreq.up_chan_id",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcc_ds_params_subtype,
     {
      "Type",
      "docsis_dccreq.ds_tlvtype",
      FT_UINT8, BASE_DEC, VALS(ds_param_subtlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_ds_params_length,
     {
      "Length",
      "docsis_dccreq.ds_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_ds_freq ,
     {
       "Frequency",
       "docsis_dccreq.ds_freq",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_mod_type ,
     {
       "Modulation Type",
       "docsis_dccreq.ds_mod_type",
       FT_UINT8, BASE_DEC, VALS (ds_mod_type_vals), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_sym_rate ,
     {
       "Symbol Rate",
       "docsis_dccreq.ds_sym_rate",
       FT_UINT8, BASE_DEC, VALS (ds_sym_rate_vals), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_intlv_depth_i ,
     {
       "Interleaver Depth I Value",
       "docsis_dccreq.ds_intlv_depth_i",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_intlv_depth_j ,
     {
       "Interleaver Depth J Value",
       "docsis_dccreq.ds_intlv_depth_j",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_chan_id ,
     {
       "Downstream Channel ID",
       "docsis_dccreq.ds_chan_id",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_sync_sub ,
     {
       "SYNC Substitution",
       "docsis_dccreq.ds_sync_sub",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ds_ofdm_block_freq ,
     {
       "OFDM Block Frequency",
       "docsis_dccreq.ds_ofdm_block_freq",
       FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_hz), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_init_tech ,
     {
       "Initialization Technique",
       "docsis_dccreq.init_tech",
       FT_UINT8, BASE_DEC, VALS (init_tech_vals), 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_ucd_sub ,
     {
       "UCD Substitution",
       "docsis_dccreq.ucd_sub",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_said_sub_cur ,
     {
       "SAID Sub - Current Value",
       "docsis_dccreq.said_sub_cur",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_said_sub_new ,
     {
       "SAID Sub - New Value",
       "docsis_dccreq.said_sub_new",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcc_sf_sub_subtype,
     {
      "Type",
      "docsis_dccreq.sf_tlvtype",
      FT_UINT8, BASE_DEC, VALS(sf_sub_subtlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_sf_sub_length,
     {
      "Length",
      "docsis_dccreq.sf_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sfid_cur ,
     {
       "SF Sub - SFID Current Value",
       "docsis_dccreq.sf_sfid_cur",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sfid_new ,
     {
       "SF Sub - SFID New Value",
       "docsis_dccreq.sf_sfid_new",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sid_cur ,
     {
       "SF Sub - SID Current Value",
       "docsis_dccreq.sf_sid_cur",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_sid_new ,
     {
       "SF Sub - SID New Value",
       "docsis_dccreq.sf_sid_new",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_sf_unsol_grant_tref ,
     {
       "SF Sub - Unsolicited Grant Time Reference",
       "docsis_dccreq.sf_unsol_grant_tref",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_cmts_mac_addr ,
     {
       "CMTS MAC Address",
       "docsis_dccreq.cmts_mac_addr",
       FT_ETHER, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccreq.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccreq_hmac_digest ,
     {
       "HMAC-DigestNumber",
       "docsis_dccreq.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* DCC-RSP */
    {&hf_docsis_dccrsp_conf_code ,
     {
       "Confirmation Code",
       "docsis_dccrsp.conf_code",
       FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_type,
     {
      "Type",
      "docsis_dccrsp.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dccrsp_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccrsp_length,
     {
      "Length",
      "docsis_dccrsp.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_cm_jump_subtype,
     {
      "Type",
      "docsis_dccrsp.cm_jump_tlvtype",
      FT_UINT8, BASE_DEC, VALS(cm_jump_subtlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcc_cm_jump_length,
     {
      "Length",
      "docsis_dccrsp.cm_jump_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccrsp_cm_jump_time_length ,
     {
       "Length of Jump",
       "docsis_dccrsp.cm_jump_time_length",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_cm_jump_time_start ,
     {
       "Start Time of Jump",
       "docsis_dccrsp.cm_jump_time_start",
       FT_UINT64, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccrsp.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccrsp_hmac_digest ,
     {
       "HMAC-Digest Number",
       "docsis_dccrsp.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* DCC-ACK */
    {&hf_docsis_dccack_type,
     {
      "Type",
      "docsis_dccack.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dccack_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccack_length,
     {
      "Length",
      "docsis_dccack.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dccack_key_seq_num ,
     {
       "Auth Key Sequence Number",
       "docsis_dccack.key_seq_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dccack_hmac_digest ,
     {
       "HMAC-DigestNumber",
       "docsis_dccack.hmac_digest",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* INIT_RNG_REQ */
    {&hf_docsis_intrngreq_sid,
     {"Service Identifier", "docsis_intrngreq.sid",
      FT_UINT16, BASE_DEC, NULL, 0x3FFF,
      NULL, HFILL}
    },
    /* DCD */
    {&hf_docsis_dcd_config_ch_cnt,
     {
       "Configuration Change Count",
       "docsis_dcd.config_ch_cnt",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_num_of_frag,
     {
       "Number of Fragments",
       "docsis_dcd.num_of_frag",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_frag_sequence_num,
     {
       "Fragment Sequence Number",
       "docsis_dcd.frag_sequence_num",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_type,
     {
      "Type",
      "docsis_dcd.tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_tlv_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_length,
     {
      "Length",
      "docsis_dcd.tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_down_classifier_subtype,
     {
      "Type",
      "docsis_dcd.down_classifier_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_down_classifier_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_down_classifier_length,
     {
      "Length",
      "docsis_dcd.down_classifier_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfr_id,
     {
       "Downstream Classifier ID",
       "docsis_dcd.cfr_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_rule_pri,
     {
       "Downstream Classifier Rule Priority",
       "docsis_dcd.cfr_rule_pri",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_subtype,
     {
      "Type",
      "docsis_dcd.cfr_ip_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_cfr_ip_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_length,
     {
      "Length",
      "docsis_dcd.cfr_ip_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_source_addr,
     {
       "Downstream Classifier IP Source Address",
       "docsis_dcd.cfr_ip_source_addr",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_source_mask,
     {
       "Downstream Classifier IP Source Mask",
       "docsis_dcd.cfr_ip_source_mask",
       FT_IPv4, BASE_NETMASK, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_dest_addr,
     {
       "Downstream Classifier IP Destination Address",
       "docsis_dcd.cfr_ip_dest_addr",
       FT_IPv4, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_ip_dest_mask,
     {
       "Downstream Classifier IP Destination Mask",
       "docsis_dcd.cfr_ip_dest_mask",
       FT_IPv4, BASE_NETMASK, NULL, 0x0,
       "Downstream Classifier IP Destination Address",
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_srcport_start,
     {
       "Downstream Classifier IP TCP/UDP Source Port Start",
       "docsis_dcd.cfr_ip_tcpudp_srcport_start",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_srcport_end,
     {
       "Downstream Classifier IP TCP/UDP Source Port End",
       "docsis_dcd.cfr_ip_tcpudp_srcport_end",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_dstport_start,
     {
       "Downstream Classifier IP TCP/UDP Destination Port Start",
       "docsis_dcd.cfr_ip_tcpudp_dstport_start",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfr_tcpudp_dstport_end,
     {
       "Downstream Classifier IP TCP/UDP Destination Port End",
       "docsis_dcd.cfr_ip_tcpudp_dstport_end",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_id,
     {
       "DSG Rule ID",
       "docsis_dcd.rule_id",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_pri,
     {
       "DSG Rule Priority",
       "docsis_dcd.rule_pri",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_ucid_list,
     {
       "DSG Rule UCID Range",
       "docsis_dcd.rule_ucid_list",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_subtype,
     {
      "Type",
      "docsis_dcd.clid_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_clid_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_clid_length,
     {
      "Length",
      "docsis_dcd.clid_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_clid_bcast_id,
     {
       "DSG Rule Client ID Broadcast ID",
       "docsis_dcd.clid_bcast_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_known_mac_addr,
     {
       "DSG Rule Client ID Known MAC Address",
       "docsis_dcd.clid_known_mac_addr",
       FT_ETHER, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_ca_sys_id,
     {
       "DSG Rule Client ID CA System ID",
       "docsis_dcd.clid_ca_sys_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_clid_app_id,
     {
       "DSG Rule Client ID Application ID",
       "docsis_dcd.clid_app_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_dsg_rule_subtype,
     {
      "Type",
      "docsis_dcd.rule_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_dsg_rule_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_dsg_rule_length,
     {
      "Length",
      "docsis_dcd.rule_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_rule_tunl_addr,
     {
       "DSG Rule Tunnel MAC Address",
       "docsis_dcd.rule_tunl_addr",
       FT_ETHER, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_cfr_id,
     {
       "DSG Rule Classifier ID",
       "docsis_dcd.rule_cfr_id",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_rule_vendor_spec,
     {
       "DSG Rule Vendor Specific Parameters",
       "docsis_dcd.rule_vendor_spec",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_subtype,
     {
      "Type",
      "docsis_dcd.cfg_tlvtype",
      FT_UINT8, BASE_DEC, VALS(dcd_cfg_vals), 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfg_length,
     {
      "Length",
      "docsis_dcd.cfg_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL,
      HFILL
     }
    },
    {&hf_docsis_dcd_cfg_chan,
     {
       "DSG Configuration Channel",
       "docsis_dcd.cfg_chan",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg1,
     {
       "DSG Initialization Timeout (Tdsg1)",
       "docsis_dcd.cfg_tdsg1",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg2,
     {
       "DSG Operational Timeout (Tdsg2)",
       "docsis_dcd.cfg_tdsg2",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg3,
     {
       "DSG Two-Way Retry Timer (Tdsg3)",
       "docsis_dcd.cfg_tdsg3",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_tdsg4,
     {
       "DSG One-Way Retry Timer (Tdsg4)",
       "docsis_dcd.cfg_tdsg4",
       FT_UINT16, BASE_DEC, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    {&hf_docsis_dcd_cfg_vendor_spec,
     {
       "DSG Configuration Vendor Specific Parameters",
       "docsis_dcd.cfg_vendor_spec",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL,
       HFILL
     }
    },
    /* MDD */
    {&hf_docsis_mdd_ccc,
     {"Configuration Change Count", "docsis_mdd.ccc",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Configuration Change Count", HFILL}
    },
    {&hf_docsis_mdd_number_of_fragments,
     {"Number of Fragments", "docsis_mdd.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Number of Fragments", HFILL}
    },
    {&hf_docsis_mdd_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_mdd.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Fragment Sequence Number", HFILL}
    },
    {&hf_docsis_mdd_current_channel_dcid,
     {"Current Channel DCID", "docsis_mdd.current_channel_dcid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Current Channel DCID", HFILL}
    },
    {&hf_docsis_mdd_tlv,
     {"TLV", "docsis_mdd.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_tlv_type,
     {"Type", "docsis_mdd.tlv.type",
      FT_UINT8, BASE_DEC, VALS(mdd_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_tlv_length,
     {"Length", "docsis_mdd.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ds_active_channel_list_subtype,
     {"Type", "docsis_mdd.downstream_active_channel_list_tlvtype",
      FT_UINT8, BASE_DEC, VALS(mdd_ds_active_channel_list_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ds_active_channel_list_length,
     {"Length", "docsis_mdd.downstream_active_channel_list_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_channel_id,
     {"Channel ID", "docsis_mdd.downstream_active_channel_list_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Downstream Active Channel List Channel ID", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_frequency,
     {"Frequency", "docsis_mdd.downstream_active_channel_list_frequency",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "MDD Downstream Active Channel List Frequency", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_annex,
     {"Annex", "docsis_mdd.downstream_active_channel_list_annex",
      FT_UINT8, BASE_DEC, VALS(J83_annex_vals), 0xF0,
      "MDD Downstream Active Channel List Annex", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_modulation_order,
     {"Modulation Order", "docsis_mdd.downstream_active_channel_list_modulation_order",
      FT_UINT8, BASE_DEC, VALS(modulation_order_vals), 0x0F,
      "MDD Downstream Active Channel List Modulation Order", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_primary_capable,
     {"Primary Capable", "docsis_mdd.downstream_active_channel_list_primary_capable",
      FT_UINT8, BASE_DEC, VALS(primary_capable_vals), 0x0,
      "MDD Downstream Active Channel List Primary Capable", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask,
     {"CM-STATUS Event Enable Bitmask", "docsis_mdd.cm_status_event_enable_bitmask",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_timeout,
     {"MDD Timeout", "docsis_mdd.downstream_active_channel_list_mdd_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0002,
      "MDD Downstream Active Channel List MDD Timeout", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_failure,
     {"QAM/FEC Lock Failure", "docsis_mdd.cm_status_event_enable_bitmask_qam_fec_lock_failure",
      FT_UINT16, BASE_DEC, NULL, 0x0004,
      "MDD Downstream Active Channel List QAM/FEC Lock Failure", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_mdd_recovery,
     {"MDD Recovery", "docsis_mdd.cm_status_event_enable_bitmask_mdd_recovery",
      FT_UINT16, BASE_DEC, NULL, 0x0010,
      "CM-STATUS event MDD Recovery", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_qam_fec_lock_recovery,
     {"QAM/FEC Lock Recovery", "docsis_mdd.cm_status_event_enable_bitmask_qam_fec_lock_recovery",
      FT_UINT16, BASE_DEC, NULL, 0x0020,
      "CM-STATUS event QAM/FEC Lock Recovery", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_map_ucd_transport_indicator,
     {"MAP and UCD transport indicator", "docsis_mdd.downstream_active_channel_list_map_ucd_transport_indicator",
      FT_UINT8, BASE_DEC, VALS(map_ucd_transport_indicator_vals), 0x0,
      "MDD Downstream Active Channel List MAP and UCD Transport Indicator", HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_fdx_sub_band_id,
     {"Full Duplex Sub-band ID", "docsis_mdd.downstream_active_channel_list_fdx_subband_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_downstream_active_channel_list_fdx_ds,
     {"FDX Downstream", "docsis_mdd.downstream_active_channel_list_fdx_ds",
      FT_UINT8, BASE_DEC, VALS(mdd_downstream_active_channel_list_fdx_vals), 0x0,
      "MDD Downstream Active Channel List FDX Downstream Indicator", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters,
     {"OFDM PLC Parameters", "docsis_mdd.ofdm_plc_parameters",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_tukey_raised_cosine_window,
     {"Tukey raised cosine window", "docsis_mdd.ofdm_plc_parameters_tukey_raised_cosine_window",
      FT_UINT8, BASE_DEC, VALS(tukey_raised_cosine_vals), 0x07,
      "OFDM PLC Parameters Tukey raised cosine window", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_cyclic_prefix,
     {"Cyclic prefix", "docsis_mdd.ofdm_plc_parameters_cyclic_prefix",
      FT_UINT8, BASE_DEC, VALS(cyclic_prefix_vals), 0x38,
      "OFDM PLC parameters Cyclic prefix", HFILL}
    },
    {&hf_docsis_mdd_ofdm_plc_parameters_sub_carrier_spacing,
     {"Sub carrier spacing", "docsis_mdd.ofdm_plc_parameters_sub_carrier_spacing",
      FT_UINT8, BASE_DEC, VALS(spacing_vals), 0x40,
      "OFDM PLC parameters Sub carrier spacing", HFILL}
    },
    {&hf_docsis_mdd_up_active_channel_list_subtype,
     {"Type", "docsis_mdd.up_active_channel_list_tlvtype",
      FT_UINT8, BASE_DEC, VALS(mdd_up_active_channel_list_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_up_active_channel_list_length,
     {"Length", "docsis_mdd.up_active_channel_list_tlvlen",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_t4_timeout,
     {"T4 timeout", "docsis_mdd.cm_status_event_enable_bitmask_t4_timeout",
      FT_UINT16, BASE_DEC, NULL, 0x0040,
      "CM-STATUS event T4 timeout", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_t3_retries_exceeded,
     {"T3 Retries Exceeded", "docsis_mdd.cm_status_event_enable_bitmask_t3_retries_exceeded",
      FT_UINT16, BASE_DEC, NULL, 0x0080,
      "CM-STATUS event T3 Retries Exceeded", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded,
     {"Successful Ranging after T3 Retries Exceeded", "docsis_mdd.cm_status_event_enable_bitmask_successful_ranging_after_t3_retries_exceeded",
      FT_UINT16, BASE_DEC, NULL, 0x0100,
      "CM-STATUS event Successful Ranging after T3 Retries Exceeded", HFILL}
    },
    {&hf_docsis_mdd_mac_domain_downstream_service_group_channel_id,
     {"Channel ID", "docsis_mdd.mac_domain_downstream_service_group_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD MAC Domain Downstream Service Group Channel ID", HFILL}
    },
    {&hf_docsis_mdd_ds_service_group_subtype,
     {"Type", "docsis_mdd.ds_service_group_type",
      FT_UINT8, BASE_DEC, VALS(mdd_ds_service_group_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ds_service_group_length,
     {"Length", "docsis_mdd.ds_service_group_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_mac_domain_downstream_service_group_md_ds_sg_identifier,
     {"MD-DS-SG Identifier", "docsis_mdd.mac_domain_downstream_service_group_md_ds_sg_identifier",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD MAC Domain Downstream Service Group MD-DS-SG Identifier", HFILL}
    },
    {&hf_docsis_mdd_downstream_ambiguity_resolution_frequency,
     {"Frequency", "docsis_mdd.downstream_ambiguity_resolution_frequency",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      "MDD Downstream Ambiguity Resolution frequency", HFILL}
    },
    {&hf_docsis_mdd_channel_profile_reporting_control_subtype,
     {"Type", "docsis_mdd.channel_profile_reporting_control_type",
      FT_UINT8, BASE_DEC, VALS(mdd_channel_profile_reporting_control_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_channel_profile_reporting_control_length,
     {"Length", "docsis_mdd.channel_profile_reporting_control_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_rcp_center_frequency_spacing,
     {"RCP Center Frequency Spacing", "docsis_mdd.rcp_center_frequency_spacing",
      FT_UINT8, BASE_DEC, VALS(rcp_center_frequency_spacing_vals), 0x0,
      "MDD RCP Center Frequency Spacing", HFILL}
    },
    {&hf_docsis_mdd_verbose_rcp_reporting,
     {"Verbose RCP reporting", "docsis_mdd.verbose_rcp_reporting",
      FT_UINT8, BASE_DEC, VALS(verbose_rcp_reporting_vals), 0x0,
      "MDD Verbose RCP Reporting", HFILL}
    },
    {&hf_docsis_mdd_fragmented_rcp_transmission,
     {"Fragmented RCP transmission", "docsis_mdd.fragmented_rcp_transmission",
      FT_UINT8, BASE_DEC, VALS(fragmented_rcp_transmission_vals), 0x0,
      "MDD Fragmented RCP transmission", HFILL}
    },
    {&hf_docsis_mdd_ip_init_param_subtype,
     {"Type", "docsis_mdd.ip_init_param_type",
      FT_UINT8, BASE_DEC, VALS(mdd_ip_init_param_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ip_init_param_length,
     {"Length", "docsis_mdd.ip_init_param_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_ip_provisioning_mode,
     {"IP Provisioning Mode", "docsis_mdd.ip_provisioning_mode",
      FT_UINT8, BASE_DEC, VALS(ip_provisioning_mode_vals), 0x0,
      "MDD IP Provisioning Mode", HFILL}
    },
    {&hf_docsis_mdd_pre_registration_dsid,
     {"Pre-registration DSID", "docsis_mdd.pre_registration_dsid",
      FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
      "MDD Pre-registration DSID", HFILL}
    },
    {&hf_docsis_mdd_early_authentication_and_encryption,
     {"Early Authentication and Encryption", "docsis_mdd.early_authentication_and_encryption",
      FT_UINT8, BASE_DEC, VALS(eae_vals), 0x0,
      "MDD Early Authentication and Encryption", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_upstream_channel_id,
     {"Upstream Channel ID", "docsis_mdd.upstream_active_channel_list_upstream_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Upstream Active Channel List - Upstream Channel ID", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_upstream_channel_priority,
     {"Upstream Channel Priority", "docsis_mdd.upstream_active_channel_list_upstream_channel_priority",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Upstream Active Channel List - Upstream Channel Priority", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds,
     {"Downstream Channel(s) on which MAPs and UCDs for this Upstream Channel are sent", "docsis_mdd.upstream_active_channel_list_dschids_maps_ucds",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "MDD Upstream Active Channel List - Downstream Channel(s) on which MAPs and UCDs for this Upstream Channel are sent", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds_dschid,
     {"Downstream Channel ID", "docsis_mdd.upstream_active_channel_list_dschids_maps_ucds.dschid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Upstream Active Channel List - ID of Downstream Channel on which MAPs and UCDs for this Upstream Channel are sent", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_fdx_upstream_channel,
     {"FDX Upstream Channel", "docsis_mdd.upstream_active_channel_list_fdx_upstream_channel",
      FT_UINT8, BASE_DEC, VALS(extended_us_channel_vals), 0x0,
      "MDD Upstream Active Channel List - FDX Upstream Channel", HFILL}
    },
    {&hf_docsis_mdd_upstream_active_channel_list_fdx_subband_id,
     {"FDX Sub-band ID", "docsis_mdd.upstream_active_channel_list_fdx_subband_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD Upstream Active Channel List - FDX Sub-band ID", HFILL}
    },
    {&hf_docsis_mdd_upstream_ambiguity_resolution_channel_list_channel_id,
     {"Channel ID", "docsis_mdd.upstream_ambiguity_resolution_channel_list_channel_id",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "MDD MAC Domain Upstream Ambiguity Resolution Channel List Channel ID", HFILL}
    },
    {&hf_docsis_mdd_upstream_frequency_range,
     {"Upstream Frequency Range", "docsis_mdd.upstream_frequency_range",
      FT_UINT8, BASE_DEC, VALS(upstream_frequency_range_vals), 0x0,
      "MDD Upstream Frequency Range", HFILL}
    },
    {&hf_docsis_mdd_symbol_clock_locking_indicator,
     {"Symbol Clock Locking Indicator", "docsis_mdd.symbol_clock_locking_indicator",
      FT_UINT8, BASE_DEC, VALS(symbol_clock_locking_indicator_vals), 0x0,
      "MDD Symbol Clock Locking Indicator", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_control_subtype,
     {"Type", "docsis_mdd.cm_status_event_control_type",
      FT_UINT8, BASE_DEC, VALS(mdd_cm_status_event_control_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_control_length,
     {"Length", "docsis_mdd.cm_status_event_control_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_event_type,
     {"Event Type", "docsis_mdd.event_type",
      FT_UINT8, BASE_DEC, VALS(symbol_cm_status_event_vals), 0x0,
      "MDD CM-STATUS Event Type", HFILL}
    },
    {&hf_docsis_mdd_maximum_event_holdoff_timer,
     {"Maximum Event Holdoff Timer (units of 20 ms)", "docsis_mdd.maximum_event_holdoff_timer",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "MDD Maximum Event Holdoff Timer", HFILL}
    },
    {&hf_docsis_mdd_maximum_number_of_reports_per_event,
     {"Maximum Number of Reports per Event", "docsis_mdd.maximum_number_of_reports_per_event",
      FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(unique_unlimited), 0x0,
      "MDD Maximum Number of Reports per Event", HFILL}
    },
    {&hf_docsis_mdd_upstream_transmit_power_reporting,
     {"Upstream Transmit Power Reporting", "docsis_mdd.upstream_transmit_power_reporting",
      FT_UINT8, BASE_DEC, VALS(upstream_transmit_power_reporting_vals), 0x0,
      "MDD Upstream Transmit Power Reporting", HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_subtype,
     {"Type", "docsis_mdd.dsg_da_to_dsid_type",
      FT_UINT8, BASE_DEC, VALS(mdd_cm_dsg_da_to_dsid_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_length,
     {"Length", "docsis_mdd.dsg_da_to_dsid_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_association_da,
     {"Destination Address", "docsis_mdd.dsg_da_to_dsid_association_da",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      "MDD DSG DA to DSID association Destination Address", HFILL}
    },
    {&hf_docsis_mdd_dsg_da_to_dsid_association_dsid,
     {"DSID", "docsis_mdd.dsg_da_to_dsid_association_dsid",
      FT_UINT24, BASE_DEC, NULL, 0x0FFFFF,
      "MDD MDD DSG DA to DSID association DSID", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events,
     {"CM-STATUS Event Enable Bitmask for Non-Channel-Specific Events", "docsis_mdd.cm_status_event_enable_non_channel_specific_events",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_sequence_out_of_range,
     {"Sequence out of range", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_sequence_out_of_range",
      FT_UINT16, BASE_DEC, NULL, 0x0008,
      "CM-STATUS event non-channel-event Sequence out of range", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup,
     {"CM operating on battery backup", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_cm_operating_on_battery_backup",
      FT_UINT16, BASE_DEC, NULL, 0x0200,
      "CM-STATUS event non-channel-event Cm operating on battery backup", HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power,
     {"Returned to AC power", "docsis_mdd.cm_status_event_enable_non_channel_specific_events_cm_returned_to_ac_power",
      FT_UINT16, BASE_DEC, NULL, 0x0400,
      "CM-STATUS event non-channel-event Cm returned to AC power", HFILL}
    },
    {&hf_docsis_mdd_extended_upstream_transmit_power_support,
     { "Extended Upstream Transmit Power Support", "docsis_mdd.extended_upstream_transmit_power_support",
       FT_BOOLEAN, BASE_NONE, TFS(&tfs_on_off), 0x0,
       "MDD Extended Upstream Transmit Power Support", HFILL}
    },
    {&hf_docsis_mdd_cmts_major_docsis_version,
     { "CMTS Major DOCSIS Version (legacy)", "docsis_mdd.cmts_major_docsis_version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cmts_minor_docsis_version,
     { "CMTS Minor DOCSIS Version (legacy)", "docsis_mdd.cmts_minor_docsis_version",
       FT_UINT8, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_tlv,
     {"TLV", "docsis_mdd.docsis_version.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_tlv_type,
     {"Type", "docsis_mdd.docsis_version.tlv.type",
      FT_UINT8, BASE_DEC, VALS(mdd_docsis_version_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_tlv_length,
     {"Length", "docsis_mdd.docsis_version.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_major_pre_40,
     { "CMTS Pre-DOCSIS 4.0 Major DOCSIS Version", "docsis_mdd.docsis_version.major_pre_40",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_minor_pre_40,
     { "CMTS Pre-DOCSIS 4.0 Minor DOCSIS Version", "docsis_mdd.docsis_version.minor_pre_40",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_major,
     { "CMTS Major DOCSIS Version", "docsis_mdd.docsis_version.major",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_minor,
     { "CMTS Minor DOCSIS Version", "docsis_mdd.docsis_version.minor",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_ext_spectrum_mode,
     {"CMTS Extended Spectrum Mode of Operation", "docsis_mdd.docsis_version.ext_spectrum_mode",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_ext_spectrum_mode_fdd,
     {"FDD", "docsis_mdd.docsis_version.fdd",
      FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE_FDD,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_docsis_version_ext_spectrum_mode_fdx,
     {"FDX", "docsis_mdd.docsis_version.fdx",
      FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), CMTS_DOCSIS_VERSION_EXT_SPECTRUM_MODE_FDX,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_periodic_maintenance_timeout_indicator,
     { "CM periodic maintenance timeout indicator", "docsis_mdd.cm_periodic_maintenance_timeout_indicator",
       FT_UINT8, BASE_DEC, VALS(cm_periodic_maintenance_timeout_indicator_vals), 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_dls_broadcast_and_multicast_delivery_method,
     { "DLS Broadcast and Multicast Delivery Method", "docsis_mdd.dls_broadcast_and_multicast_delivery_method",
       FT_UINT8, BASE_DEC, VALS(dls_broadcast_and_multicast_delivery_method_vals), 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_ofdm_prof_fail,
     { "Downstream OFDM Profile Failure", "docsis_mdd.cm_status_event_d31_ofdm_prof_fail",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000001,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_prim_down_chan_change,
     { "Primary Downstream Channel Change", "docsis_mdd.cm_status_event_d31_prim_down_chan_change",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000002,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_dpd_mismatch,
     { "DPD Mismatch", "docsis_mdd.cm_status_event_d31_dpd_mismatch",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000004,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_deprecated,
     { "Deprecated", "docsis_mdd.cm_status_event_d31_deprecated",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000008,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_ncp_prof_fail,
     { "NCP Profile Failure", "docsis_mdd.cm_status_event_d31_ncp_prof_fail",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000010,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_loss_fec_plc,
     { "Loss of FEC lock on PLC", "docsis_mdd.cm_status_event_d31_loss_fec_plc",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000020,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_ncp_prof_recover,
     { "NCP Profile Recovery", "docsis_mdd.cm_status_event_d31_ncp_prof_recover",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000040,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_fec_recover_on_plc,
     { "FEC Recovery on PLC", "docsis_mdd.cm_status_event_d31_fec_recover_on_plc",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000080,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_fec_recover_on_ofdm_prof,
     { "FEC Recovery on OFDM Profile", "docsis_mdd.cm_status_event_d31_fec_recover_on_ofdm_prof",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000100,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_ofdma_prof_fail,
     { "OFDMA Profile Failure", "docsis_mdd.cm_status_event_d31_ofdma_prof_fail",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000200,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_map_stor_overflow_ind,
     { "MAP Storage Overflow Indicator", "docsis_mdd.cm_status_event_d31_map_stor_overflow_ind",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000400,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_ofdm_map_stor_almost_full_ind,
     { "MAP Storage Almost Full Indicator", "docsis_mdd.cm_status_event_d31_ofdm_map_stor_almost_full_ind",
       FT_BOOLEAN, 32, TFS(&tfs_enabled_disabled), 0x00000800,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_cm_status_event_d31_reserved,
     { "Reserved for future use", "docsis_mdd.cm_status_event_d31_reserved",
       FT_UINT32, BASE_HEX, NULL, 0xFFFFF000,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_band_edge,
     { "Diplexer Band Edge", "docsis_mdd.diplexer_band_edge",
       FT_UINT8, BASE_DEC, VALS(mdd_diplexer_band_edge_vals), 0x0,
       NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_band_edge_length,
     {"Length", "docsis_mdd.diplexer_band_edge_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_us_upper_band_edge,
     {"Diplexer Upstream Upper Band Edge", "docsis_mdd.diplexer_us_upper_band_edge",
      FT_UINT8, BASE_DEC, VALS(mdd_diplexer_us_upper_band_edge_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_ds_lower_band_edge,
     {"Diplexer Downstream Lower Band Edge", "docsis_mdd.diplexer_ds_lower_band_edge",
      FT_UINT8, BASE_DEC, VALS(mdd_diplexer_ds_lower_band_edge_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_ds_upper_band_edge,
     {"Diplexer Downstream Upper Band Edge", "docsis_mdd.diplexer_ds_upper_band_edge",
      FT_UINT8, BASE_DEC, VALS(mdd_diplexer_ds_upper_band_edge_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_us_upper_band_edge_override,
     {"Diplexer Upstream Upper Band Edge Override", "docsis_mdd.diplexer_us_upper_band_edge_override",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_ds_lower_band_edge_override,
     {"Diplexer Downstream Lower Band Edge Override", "docsis_mdd.diplexer_ds_lower_band_edge_override",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_diplexer_ds_upper_band_edge_override,
     {"Diplexer Downstream Upper Band Edge Override", "docsis_mdd.diplexer_ds_upper_band_edge_override",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_mhz), 0x0,
      NULL, HFILL}
    },
    /* MDD Advanced Band Plan Descriptor */
    {&hf_docsis_mdd_abp_tlv,
     {"TLV", "docsis_mdd.advanced_band_plan.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_abp_tlv_type,
     {"Type", "docsis_mdd.advanced_band_plan.tlv.type",
      FT_UINT8, BASE_DEC, VALS(mdd_abp_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_abp_tlv_length,
     {"Length", "docsis_mdd.advanced_band_plan.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_abp_sub_band_count,
     {"Total number of sub-bands", "docsis_mdd.advanced_band_plan.subband_count",
      FT_UINT8, BASE_DEC, VALS(mdd_abp_sub_band_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_mdd_abp_sub_band_width,
     {"Full Duplex Sub-band Width", "docsis_mdd.advanced_band_plan.subband_width",
      FT_UINT8, BASE_DEC, VALS(mdd_abp_sub_band_width_vals), 0x0, NULL, HFILL}
    },
    /* MDD BPI+*/
    {&hf_docsis_mdd_bpi_plus_tlv,
     {"TLV", "docsis_mdd.bpi_plus.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_bpi_plus_tlv_type,
     {"Type", "docsis_mdd.bpi_plus.tlv.type",
      FT_UINT8, BASE_DEC, VALS(mdd_bpi_plus_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_bpi_plus_tlv_length,
     {"Length", "docsis_mdd.bpi_plus.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mdd_bpi_plus_version,
     {"Version", "docsis_mdd.bpi_plus.version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "BPI+ Version Number", HFILL}
    },
    {&hf_docsis_mdd_bpi_plus_cfg,
     {"Configuration", "docsis_mdd.bpi_plus.cfg",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "BPI+ Configuration Bitmask", HFILL}
    },
    {&hf_docsis_mdd_bpi_plus_cfg_eae,
     {"Early Authentication and Encryption", "docsis_mdd.bpi_plus.eae",
      FT_BOOLEAN, 8, TFS(&tfs_enabled_disabled), 0x80,
      NULL, HFILL}
    },
    /* B_INIT_RNG_REQ */
    {&hf_docsis_bintrngreq_capflags,
     {"Capability Flags", "docsis_bintrngreq.capflags",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_bintrngreq_capflags_frag,
     {"Pre-3.0 Fragmentation", "docsis_bintrngreq.capflags.frag",
      FT_BOOLEAN, 8, NULL, (1<<7),
      "Pre-3.0 DOCSIS fragmentation is supported prior to registration", HFILL }
    },
    {&hf_docsis_bintrngreq_capflags_encrypt,
     {"Early Auth. & Encrypt", "docsis_bintrngreq.capflags.encrypt",
      FT_BOOLEAN, 8, NULL, (1<<6),
      "Early Authentication and Encryption supported", HFILL }
    },
    {&hf_docsis_bintrngreq_mddsgid,
     {"MD-DS-SG-ID", "docsis_bintrngreq.mddsgid",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      "MAC Domain Downstream Service Group Identifier", HFILL}
    },
    /* DBC_REQ */
    {&hf_docsis_dbcreq_number_of_fragments,
     {"Number of Fragments", "docsis_dbcreq.number_of_fragments",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dbcreq_fragment_sequence_number,
     {"Fragment Seq No", "docsis_dbcreq.fragment_sequence_number",
      FT_UINT8, BASE_HEX_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* DBC_RSP */
    {&hf_docsis_dbcrsp_conf_code,
     {"Confirmation Code", "docsis_dbcrsp.conf_code",
      FT_UINT8, BASE_DEC|BASE_EXT_STRING, &docsis_conf_code_ext, 0x0,
      NULL, HFILL}
    },
    /* DPV_REQ/RSP */
    {&hf_docsis_dpv_flags,
     {"Flags", "docsis_dpv.flags",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_us_sf,
     {"Upstream Service Flow ID", "docsis_dpv.us_sf",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_n,
     {"N (Measurement avaraging factor)", "docsis_dpv.n",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_start,
     {"Start Reference Point", "docsis_dpv.start",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_end,
     {"End Reference Point", "docsis_dpv.end",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_ts_start,
     {"Timestamp Start", "docsis_dpv.ts_start",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpv_ts_end,
     {"Timestamp End", "docsis_dpv.ts_end",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    /* CM Status */
    {&hf_docsis_cmstatus_e_t_mdd_t,
     {"Event Type: Secondary Channel MDD timeout", "docsis_cmstatus.mdd_timeout", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_qfl_f,
     {"Event Type: QAM/FEC lock failure", "docsis_cmstatus.qam_fec_lock_failure", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_s_o,
     {"Event Type: Sequence out-of-range", "docsis_cmstatus.sequence_out_of_range", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_mdd_r,
     {"Event Type: Secondary Channel MDD Recovery", "docsis_cmstatus.mdd_recovery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_qfl_r,
     {"Event Type: QAM/FEC Lock Recovery", "docsis_cmstatus.qam_fec_lock_recovery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_t4_t,
     {"Event Type: T4 timeout", "docsis_cmstatus.t4_timeout", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_t3_e,
     {"Event Type: T3 retries exceeded", "docsis_cmstatus.t3_retries_exceeded", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_rng_s,
     {"Event Type: Successful ranging after T3 retries exceeded", "docsis_cmstatus.successful_ranging_after_t3_retries_exceeded", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_cm_b,
     {"Event Type: CM operating on battery backup", "docsis_cmstatus.cm_on_battery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_cm_a,
     {"Event Type: CM returned to A/C power", "docsis_cmstatus.cm_on_ac_power", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_mac_removal,
     {"Event Type: MAC Removal event", "docsis_cmstatus.mac_removal", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_ds_ofdm_profile_failure,
     {"Event Type: DS OFDM profile failure", "docsis_cmstatus.ds_ofdm_profile_failure", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_prim_ds_change,
     {"Event Type: Primary Downstream Change", "docsis_cmstatus.primary_downstream_change", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_dpd_mismatch,
     {"Event Type: DPD Mismatch", "docsis_cmstatus.dpd_mismatch", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_ncp_profile_failure,
     {"Event Type: NCP Profile failure", "docsis_cmstatus.ncp_profile_failure", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_plc_failure,
     {"Event Type: PLC failure", "docsis_cmstatus.plc_failure", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_ncp_profile_recovery,
     {"Event Type: NCP profile recovery", "docsis_cmstatus.ncp_profile_recovery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_plc_recovery,
     {"Event Type: PLC recovery", "docsis_cmstatus.plc_recovery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_ofdm_profile_recovery,
     {"Event Type: OFDM profile recovery", "docsis_cmstatus.ofdm_profile_recovery", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_ofdma_profile_failure,
     {"Event Type: OFDMA profile failure", "docsis_cmstatus.ofdma_profile_failure", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_map_storage_overflow_indicator,
     {"Event Type: MAP Storage overflow indicator", "docsis_cmstatus.map_storage_overflow_indicator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_map_storage_almost_full_indicator,
     {"Event Type: MAP Storage almost full indicator", "docsis_cmstatus.map_storage_almost_full_indicator", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_e_t_unknown,
     {"Unknown Event Type", "docsis_cmstatus.unknown_event_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_descr,
     {"Description", "docsis_cmstatus.status_event.description", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_ds_ch_id,
     {"Downstream Channel ID", "docsis_cmstatus.status_event.ds_chid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_us_ch_id,
     {"Upstream Channel ID", "docsis_cmstatus.status_event.us_chid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_dsid,
     {"DSID", "docsis_cmstatus.status_event.dsid", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_mac_address,
     {"MAC Address", "docsis_cmstatus.status_event.mac_address", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_ds_ofdm_profile_id,
     {"Downstream OFDM Profile ID", "docsis_cmstatus.status_event.ds_ofdm_profile_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_us_ofdma_profile_id,
     {"US OFDMA Profile ID", "docsis_cmstatus.status_event.us_ofdma_profile_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_tlv_data,
     {"TLV Data", "docsis_cmstatus.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_type,
     {"Type", "docsis_cmstatus.type", FT_UINT8, BASE_DEC, VALS(cmstatus_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_length,
     {"Length", "docsis_cmstatus.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_tlv_data,
     {"Status Event TLV Data", "docsis_cmstatus.status_event.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_type,
     {"Status Event Type", "docsis_cmstatus.status_event.type", FT_UINT8, BASE_DEC, VALS(cmstatus_status_event_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_cmstatus_status_event_length,
     {"Status Event Length", "docsis_cmstatus.status_event.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },

    /* CM_CTRL_REQ */
    {&hf_docsis_cmctrl_tlv_mute,
     {"Upstream Channel RF Mute", "docsis_cmctrl.mute",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_mute_timeout,
     {"RF Mute Timeout Interval", "docsis_cmctrl.mute_timeout",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_reinit,
     {"CM Reinitialize", "docsis_cmctrl.reinit",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_disable_fwd,
     {"Disable Forwarding", "docsis_cmctrl.disable_fwd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_ds_event,
     {"Override Downstream Events", "docsis_cmctrl.ds_event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_us_event,
     {"Override Upstream Events", "docsis_cmctrl.us_event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_tlv_event,
     {"Override Non-Channel-Specific Events", "docsis_cmctrl.event",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_tlv_data,
     {"TLV Data", "docsis_cmctrl.tlv_data",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_type,
     {"Type", "docsis_cmctrl.tlv_type",
      FT_UINT8, BASE_DEC, VALS(cmctrlreq_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_length,
     {"Length", "docsis_cmctrl.tlv_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_us_type,
     {"Type", "docsis_cmctrl.us_event_type",
      FT_UINT8, BASE_DEC, VALS(cmctrlreq_us_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrlreq_us_length,
     {"Length", "docsis_cmctrl.us_event_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_us_event_ch_id,
     {"Upstream Channel ID", "docsis_cmctrl.us_event.chid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_us_event_mask,
     {"Upstream Status Event Enable Bitmask", "docsis_cmctrl.us_event.mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_type,
     {"Type", "docsis_cmctrl.ds_event_type",
      FT_UINT8, BASE_DEC, VALS(cmctrlreq_ds_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_length,
     {"Length", "docsis_cmctrl.ds_event_length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_event_ch_id,
     {"Downstream Channel ID", "docsis_cmctrl.ds_event.chid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cmctrl_ds_event_mask,
     {"Downstream Status Event Enable Bitmask", "docsis_cmctrl.ds_event.mask",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    /* REG_REQ_MP */
    {&hf_docsis_regreqmp_sid,
     {"Sid", "docsis_regreqmp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Sid", HFILL}
    },
    {&hf_docsis_regreqmp_number_of_fragments,
     {"Number of Fragments", "docsis_regreqmp.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Number of Fragments", HFILL}
    },
    {&hf_docsis_regreqmp_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_regreqmp.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Req-Mp Fragment Sequence Number", HFILL}
    },
    /* REG_RSP_MP */
    {&hf_docsis_regrspmp_sid,
     {"Sid", "docsis_regrspmp.sid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Sid", HFILL}
    },
    {&hf_docsis_regrspmp_response,
     {"Response", "docsis_regrspmp.response",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Response", HFILL}
    },
    {&hf_docsis_regrspmp_number_of_fragments,
     {"Number of Fragments", "docsis_regrspmp.number_of_fragments",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Number of Fragments", HFILL}
    },
    {&hf_docsis_regrspmp_fragment_sequence_number,
     {"Fragment Sequence Number", "docsis_regrspmp.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Reg-Rsp-Mp Fragment Sequence Number", HFILL}
    },
    /* EM */
    {&hf_docsis_emrsp_tlv_data,
     {"Energy Management TLV data", "docsis_emrsp.tlv_data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emrsp_tlv_type,
     {"Energy Management TLV Type", "docsis_emrsp.tlv.type",
      FT_UINT8, BASE_DEC, VALS(emrsp_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emrsp_tlv_length,
     {"Energy Management TLV Length", "docsis_emrsp.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emrsp_tlv_holdoff_timer,
     {"Hold-Off Timer", "docsis_emrsp.tlv.holdoff_timer",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emreq_req_power_mode,
     {"Requested Power Mode", "docsis_emreq.req_power_mode",
      FT_UINT8, BASE_DEC, VALS(emreq_req_power_mode_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emreq_reserved,
     {"Reserved", "docsis_emreq.reserved",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emrsp_rsp_code,
     {"Response Code", "docsis_emrsp.resp_code",
      FT_UINT8, BASE_DEC, VALS(emrsp_rsp_code_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emrsp_reserved,
     {"Reserved", "docsis_emrsp.reserved",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_emrsp_tlv_unknown,
      {"Unknown TLV", "docsis_emrsp.unknown_tlv",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    /* OCD */
    {&hf_docsis_ocd_tlv_unknown,
      {"Unknown TLV", "docsis_ocd.unknown_tlv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_ccc,
      {"Configuration Change Count", "docsis_ocd.ccc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_four_trans_size,
      {"Discrete Fourier Transform Size", "docsis_ocd.tlv.four_trans_size", FT_UINT8, BASE_DEC, VALS (docsis_ocd_four_trans_size), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_cycl_pref,
      {"Cyclic Prefix", "docsis_ocd.tlv.cyc_pref", FT_UINT8, BASE_DEC, VALS (docsis_ocd_cyc_prefix), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_roll_off,
      {"Roll Off", "docsis_ocd.tlv.roll_off", FT_UINT8, BASE_DEC, VALS (docsis_ocd_roll_off), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_ofdm_spec_loc,
      {"OFDM Spectrum Location", "docsis_ocd.tlv.ofdm_spec_loc", FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_hz), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_time_int_depth,
      {"Time Interleaving Depth", "docsis_ocd.tlv.time_int_depth", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_prim_cap_ind,
      {"Primary Capable Indicator", "docsis_ocd.tlv.prim_cap_ind", FT_UINT8, BASE_DEC, VALS(docsis_ocd_prim_cap_ind_str), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_fdx_ind,
      {"FDX Indicator", "docsis_ocd.tlv.fdx_indicator", FT_UINT8, BASE_DEC, VALS(docsis_ocd_fdx_ind_str), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_subc_assign_type,
      {"Assignment type", "docsis_ocd.tlv.subc_assign.type", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_type_str), 0xC0, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_subc_assign_value,
      {"Assignment value", "docsis_ocd.tlv.subc_assign.value", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_value_str), 0x20, NULL, HFILL}
    },
    {&hf_docsis_ocd_subc_assign_subc_type,
      {"Subcarrier Type", "docsis_ocd.tlv.subc_assign.subc_type", FT_UINT8, BASE_DEC, VALS(docsis_ocd_subc_assign_subc_type_str), 0x1F, NULL, HFILL}
    },
    {&hf_docsis_ocd_subc_assign_range,
      {"Subcarrier index range", "docsis_ocd.tlv.subc_assign.range", FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00, NULL, HFILL}
    },
    {&hf_docsis_ocd_subc_assign_index,
      {"Subcarrier index", "docsis_ocd.tlv.subc_assign.index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    {&hf_docsis_ocd_tlv_data,
     {"TLV Data", "docsis_ocd.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_type,
     {"Type", "docsis_ocd.type", FT_UINT8, BASE_DEC, VALS(ocd_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_ocd_length,
     {"Length", "docsis_ocd.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    /* DPD */
    {&hf_docsis_dpd_tlv_unknown,
     {"Unknown TLV", "docsis_dpd.unknown_tlv",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpd_prof_id,
     {"Profile Identifier", "docsis_dpd.prof_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_ccc,
     {"Configuration Change Count", "docsis_dpd.ccc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_type,
      {"Subcarrier Assignment Type", "docsis_dpd.tlv.subc_assign.type", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_type_str), 0xC0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_value,
      {"Subcarrier Assignment Value", "docsis_dpd.tlv.subc_assign.value", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_value_str), 0x20, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_reserved,
      {"reserved", "docsis_dpd.tlv.subc_assign.reserved", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_modulation,
     {"Subcarrier Assignment Modulation", "docsis_dpd.tlv.subc_assign.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_subc_assign_modulation_str), 0x0F, NULL, HFILL}
    },
    {&hf_docsis_dpd_subc_assign_range,
     {"Subcarrier index range", "docsis_dpd.tlv.subc_assign.range", FT_UINT32, BASE_CUSTOM, CF_FUNC(subc_assign_range), 0x00, NULL, HFILL}
    },
    {&hf_docsis_dpd_subc_assign_index,
     {"Subcarrier index", "docsis_dpd.tlv.subc_assign.index", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_oddness,
     {"Odd or even", "docsis_dpd.tlv.subc_assign_vect.oddness", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_oddness_str), 0x80, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_reserved,
     {"Reserved", "docsis_dpd.tlv.subc_assign_vect.reserved", FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_subc_start,
     {"Subcarrier start", "docsis_dpd.tlv.subc_assign_vect.subc_start", FT_UINT16, BASE_DEC, NULL, 0x1FFF, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_modulation_odd,
     {"Modulation", "docsis_dpd.tlv.subc_assign_vect.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_modulation_str), 0xF0, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_subc_assign_vector_modulation_even,
     {"Modulation", "docsis_dpd.tlv.subc_assign_vect.modulation", FT_UINT8, BASE_DEC, VALS(docsis_dpd_tlv_subc_assign_vector_modulation_str), 0x0F, NULL, HFILL}
    },
    {&hf_docsis_dpd_tlv_data,
     {"TLV Data", "docsis_dpd.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_type,
     {"Type", "docsis_dpd.type" ,FT_UINT8, BASE_DEC, VALS(dpd_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpd_length,
     {"Length", "docsis_dpd.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    /* OPT-REQ */
    {&hf_docsis_optreq_tlv_unknown,
     {"Unknown TLV", "docsis_optreq.unknown_tlv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_reserved,
     {"Reserved", "docsis_optreq.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_prof_id,
     {"Profile Identifier", "docsis_optreq.prof_id", FT_UINT8, BASE_DEC, VALS(profile_id_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_opcode,
     {"Opcode", "docsis_optreq.opcode", FT_UINT8, BASE_DEC, VALS(opt_opcode_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_data,
     {"TLV Data", "docsis_optreq.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_type,
     {"Type", "docsis_optreq.type", FT_UINT8, BASE_DEC, VALS(optreq_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_length,
     {"Length", "docsis_optreq.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_rxmer_stat_subc,
     {"RxMER Statistics per subcarrier", "docsis_optreq.reqstat.rxmer_stat_per_subcarrier", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x1, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_rxmer_subc_threshold_comp,
     {"RxMER per Subcarrier Threshold Comparison for Candidate Profile", "docsis_optreq.reqstat.rxmer_per_subcarrier_thresh_comp", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x2, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_snr_marg_cand_prof,
     {"SNR Margin for Candidate Profile", "docsis_optreq.reqstat.snr_marg_cand_prof", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x4, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_codew_stat_cand_prof,
     {"Codeword Statistics for Candidate Profile", "docsis_optreq.reqstat.codew_stat_cand_prof", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x8, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_codew_thresh_comp_cand_prof,
     {"Codeword Threshold Comparison for Candidate Profile", "docsis_optreq.reqstat.codew_thresh_comp_cand_prof", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x00000010, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_ncp_field_stat,
     {"NCP Field Statistics", "docsis_optreq.reqstat.ncp_field_stats", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x00000020, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_ncp_crc_thresh_comp,
     {"NCP CRC Threshold Comparison", "docsis_optreq.reqstat.ncp_crc_thresh_comp", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x00000040, NULL, HFILL}
    },
    {&hf_docsis_optreq_reqstat_reserved,
     {"Reserved", "docsis_optreq.reqstat.reserved", FT_BOOLEAN, 32, TFS(&tfs_requested_not_requested), 0x00000080, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_rxmer_thresh_data,
     {"TLV Data", "docsis_optreq.rxmer_thresh_params.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_xmer_thresh_params_type,
     {"Type", "docsis_optreq.rxmer_thres_params.type", FT_UINT8, BASE_DEC, VALS(optreq_tlv_rxmer_thresh_params_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_xmer_thresh_params_length,
     {"Length", "docsis_optreq.rxmer_thres_params.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_rxmer_thresh_data_mod_order,
     {"Modulation Order", "docsis_optreq.rxmer_thres_params.mod_order", FT_UINT8, BASE_DEC, VALS(opreq_tlv_rxmer_thresh_params_mod_order), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_data,
     {"TLV Data", "docsis_optreq.trigger_definition.tlv_data", FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_data_type,
     {"Type", "docsis_optreq.trigger_definition.type", FT_UINT8, BASE_DEC, VALS(optreq_tlv_trigger_definition_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_data_length,
     {"Length", "docsis_optreq.trigger_definition.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_trigger_type,
     {"Trigger Type", "docsis_optreq.trigger_definition.trigger_type", FT_UINT8, BASE_DEC, VALS(optreq_tlv_triggered_definition_trigger_type_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_measure_duration,
     {"Measurement Duration", "docsis_optreq.trigger_definition.measurement_duration", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_triggering_sid,
     {"Triggering SID", "docsis_optreq.trigger_definition.triggering_sid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_us_chan_id,
     {"US Channel ID", "docsis_optreq.trigger_definition.us_chan_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_sound_ambig_offset,
     {"OUDP Sounding Ambiguity Offset", "docsis_optreq.trigger_definition.sound_ambig_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_rx_mer_to_report,
     {"RxMER Measurement to Report", "docsis_optreq.trigger_definition.rx_mer_to_report", FT_UINT8, BASE_DEC, VALS(optreq_tlv_triggered_definition_rx_mer_to_report_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optreq_tlv_trigger_definition_start_time,
     {"Time-Triggered Start Time", "docsis_optreq.trigger_definition.start_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    /* OPT-RSP */
    {&hf_docsis_optrsp_reserved,
     {"Reserved", "docsis_optrsp.reserved",
      FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_prof_id,
     {"Profile Identifier", "docsis_optrsp.prof_id",
      FT_UINT8, BASE_DEC, VALS(profile_id_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_status,
     {"Status", "docsis_optrsp.status",
      FT_UINT8, BASE_DEC, VALS(opt_status_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_tlv,
     {"TLV", "docsis_optrsp.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_tlv_type,
     {"Type", "docsis_optrsp.tlv.type",
      FT_UINT8, BASE_DEC, VALS(optrsp_tlv_vals), 0x0, "OPT-RSP TLV type", HFILL}
    },
    {&hf_docsis_optrsp_tlv_length,
     {"Length", "docsis_optrsp.tlv.length",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_tlv,
     {"TLV", "docsis_optrsp.rxmer_snr_margin.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_tlv_type,
     {"Type", "docsis_optrsp.rxmer_snr_margin.tlv.type",
      FT_UINT8, BASE_DEC, VALS(optrsp_rxmer_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_tlv_length,
     {"Length", "docsis_optrsp.rxmer_snr_margin.tlv.length",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_subcarrier,
     {"RxMER", "docsis_optrsp.rxmer_snr_margin.rxmer_per_subc",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_subcarrier_threshold,
     {"Result", "docsis_optrsp.rxmer_snr_margin.threshold_per_subc",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      "RxMER per Subcarrier Threshold Comparison Result", HFILL}
    },
    {&hf_docsis_optrsp_rxmer_subcarrier_threshold_count,
     {"Number of Subcarriers", "docsis_optrsp.rxmer_snr_margin.threshold_count",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      "Number of Subcarriers whose RxMER is RxMER Margin below the RxMER Target", HFILL}
    },
    {&hf_docsis_optrsp_rxmer_snr_margin,
     {"SNR Margin", "docsis_optrsp.rxmer_snr_margin.snr_margin",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_avg,
     {"Average RxMER", "docsis_optrsp.rxmer_snr_margin.rxmer_avg",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_ect_rba_subband_direction,
     {"ECT RxMER Probe-Triggered RBA Sub-band Direction Set", "docsis_optrsp.rxmer_snr_margin.ect_rba_subband_direction",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb0,
     {"Direction Sub-band 0", "docsis_optrsp.rxmer_snr_margin.ect_rba_subband_direction.0",
      FT_BOOLEAN, 8, TFS(&tfs_up_down), 0x04, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb1,
     {"Direction Sub-band 1", "docsis_optrsp.rxmer_snr_margin.ect_rba_subband_direction.1",
      FT_BOOLEAN, 8, TFS(&tfs_up_down), 0x02, NULL, HFILL}
    },
    {&hf_docsis_optrsp_rxmer_ect_rba_subband_direction_sb2,
     {"Direction Sub-band 2", "docsis_optrsp.rxmer_snr_margin.ect_rba_subband_direction.2",
      FT_BOOLEAN, 8, TFS(&tfs_up_down), 0x01, NULL, HFILL}
    },
    {&hf_docsis_optrsp_data_cw_tlv,
     {"TLV", "docsis_optrsp.data_cw.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_data_cw_tlv_type,
     {"Type", "docsis_optrsp.data_cw.tlv.type",
      FT_UINT8, BASE_DEC, VALS(optrsp_data_cw_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_data_cw_tlv_length,
     {"Length", "docsis_optrsp.data_cw.tlv.length",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_data_cw_count,
     {"Codeword Count", "docsis_optrsp.data_cw.count",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_data_cw_corrected,
     {"Corrected Codeword Count", "docsis_optrsp.data_cw.corrected",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_data_cw_uncorrectable,
     {"Uncorrectable Codeword Count", "docsis_optrsp.data_cw.uncorrectable",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_data_cw_threshold_comparison,
     {"Comparison Result", "docsis_optrsp.data_cw.threshold_comparison",
      FT_UINT8, BASE_DEC, VALS(optrsp_data_cw_threshold_comparison_vals), 0x0,
      "Codeword Threshold Comparison Result for Candidate Profile", HFILL}
    },
    {&hf_docsis_optrsp_ncp_fields_tlv,
     {"TLV", "docsis_optrsp.ncp_fields.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_ncp_fields_tlv_type,
     {"Type", "docsis_optrsp.ncp_fields.tlv.type",
      FT_UINT8, BASE_DEC, VALS(optrsp_ncp_fields_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_ncp_fields_tlv_length,
     {"Length", "docsis_optrsp.ncp_fields.tlv.length",
      FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_ncp_fields_count,
     {"NCP Fields Count", "docsis_optrsp.ncp_fields.count",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_ncp_fields_failure,
     {"NCP CRC Failure Count", "docsis_optrsp.ncp_fields.failure",
      FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_optrsp_ncp_fields_threshold_comparison,
     {"Comparison Result", "docsis_optrsp.ncp_fields.threshold_comparison",
      FT_UINT8, BASE_DEC, VALS(optrsp_ncp_fields_threshold_comparison_vals), 0x0,
      "NCP CRC Threshold Comparison Result", HFILL
     }
    },
    /* OPT-ACK */
    {&hf_docsis_optack_prof_id,
     {"Profile Identifier", "docsis_optack.prof_id", FT_UINT8, BASE_DEC, VALS(profile_id_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_optack_reserved,
     {"Reserved", "docsis_optack.reserved", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    /* RBA */
    {&hf_docsis_rba_tg_id,
     {"Transmission Group ID", "docsis_rba.tg_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_rba_ccc,
     {"Change Count", "docsis_rba.ccc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_rba_dcid,
     {"Current Channel DCID", "docsis_rba.dcid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_rba_control_byte_bitmask,
     {"Control byte bitmask", "docsis_rba.control_byte_bitmask", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL}
    },
    {&hf_docsis_rba_resource_block_change_bit,
     {"Resource Block Change bit", "docsis_rba.rb_change_bit", FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL}
    },
    {&hf_docsis_rba_expiration_time_valid_bit,
     {"Expiration Time Valid bit", "docsis_rba.exp_time_valid_bit", FT_UINT8, BASE_HEX, NULL, 0x02, NULL, HFILL}
    },
    {&hf_docsis_rba_control_byte_bitmask_rsvd,
     {"Control byte bitmask reserved", "docsis_rba.control_byte_bitmask_rsvd", FT_UINT8, BASE_HEX, NULL, 0xFC, NULL, HFILL}
    },
    {&hf_docsis_rba_rba_time,
     {"RBA Time", "docsis_rba.rba_time", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_rba_rba_expiration_time,
     {"RBA Expiration Time", "docsis_rba.rba_expiration_time", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_rba_number_of_subbands,
     {"Number of Sub-bands", "docsis_rba.nr_subbands", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_rba_subband_direction,
     {"Sub-band direction", "docsis_rba.subband_direction", FT_UINT8, BASE_DEC, VALS(rba_subband_direction_vals), 0x0, NULL, HFILL}
    },
    /* CWT-REQ and CWT-RSP */
    {&hf_docsis_cwt_trans_id,
     {"Transaction ID", "docsis_cwt.trans_id",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cwt_sub_band_id,
     {"Sub-band ID", "docsis_cwt.subband_id",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cwt_op_code,
     {"Operation Code", "docsis_cwt.op_code",
      FT_UINT8, BASE_DEC, VALS(cwt_op_code_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_cwt_status,
     {"Status", "docsis_cwt.status",
      FT_UINT8, BASE_DEC, VALS(cwt_status_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_cwt_tlv,
     {"TLV", "docsis_cwt.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cwt_tlv_type,
     {"Type", "docsis_cwt.tlv.type",
      FT_UINT8, BASE_DEC, VALS(cwt_tlv_vals), 0x0, NULL, HFILL}
    },
    {&hf_docsis_cwt_tlv_length,
     {"Length", "docsis_cwt.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_cwt_phase_rotation,
     {"Phase Rotation", "docsis_cwt.phase_rotation",
      FT_UINT8, BASE_DEC, VALS(cwt_phase_rotation_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cwt_max_duration,
     {"Maximum Duration", "docsis_cwt.max_duration",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cwt_us_encodings_tlv,
     {"TLV", "docsis_cwt.us_encodings.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cwt_us_encodings_tlv_type,
     {"Type", "docsis_cwt.us_encodings.tlv.type",
      FT_UINT8, BASE_DEC, VALS(cwt_us_encodings_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cwt_us_encodings_tlv_length,
     {"Length", "docsis_cwt.us_encodings.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cwt_us_encodings_cid,
     {"Extended Upstream Channel ID", "docsis_cwt.us_encodings.cid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cwt_us_encodings_sc_index,
     {"Upstream Subcarrier Index", "docsis_cwt.us_encodings.sc_index",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_cwt_us_encodings_power_boost,
     {"CWT Power Boost", "docsis_cwt.us_encodings.power_boost",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0,
      NULL, HFILL}
    },
    /* ECT-REQ and ECT-RSP */
    {&hf_docsis_ect_trans_id,
    {"Transaction ID", "docsis_ect.trans_id",
      FT_UINT16, BASE_CUSTOM, CF_FUNC(ect_trans_id_val), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_rsp_code,
    {"Response Code", "docsis_ect.rsp_code",
      FT_UINT8, BASE_DEC, VALS(ect_rsp_code_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_tlv,
    {"TLV", "docsis_ect.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_tlv_type,
    {"Type", "docsis_ect.tlv.type",
      FT_UINT8, BASE_DEC, VALS(ect_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_tlv_length,
    {"Length", "docsis_ect.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_tlv,
    {"TLV", "docsis_ect.control.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_tlv_type,
    {"Type", "docsis_ect.control.tlv.type",
      FT_UINT8, BASE_DEC, VALS(ect_control_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_tlv_length,
    {"Length", "docsis_ect.control.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_subband_direction,
    {"Direction", "docsis_ect.control.subband_direction",
      FT_UINT8, BASE_DEC, VALS(rba_subband_direction_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_status,
    {"Training Status", "docsis_ect.control.status",
      FT_UINT8, BASE_DEC, VALS(ect_control_status_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_tlv,
    {"TLV", "docsis_ect.control.method.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_tlv_type,
    {"Type", "docsis_ect.control.method.tlv.type",
      FT_UINT8, BASE_DEC, VALS(ect_control_method_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_tlv_length,
    {"Length", "docsis_ect.control.method.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_fg_tlv,
    {"TLV", "docsis_ect.control.method.fg.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_fg_tlv_type,
    {"Type", "docsis_ect.control.method.fg.tlv.type",
      FT_UINT8, BASE_DEC, VALS(ect_control_method_fg_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_fg_tlv_length,
    {"Length", "docsis_ect.control.method.fg.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_fg_duration,
    {"Duration", "docsis_ect.control.method.fg.duration",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_symbols), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_fg_periodicity,
    {"Periodicity", "docsis_ect.control.method.fg.periodicity",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_fg_expiration_time,
    {"Expiration Time", "docsis_ect.control.method.fg.expiration_time",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_fg_ds_zbl,
    {"Downstream Zero Bit Loading", "docsis_ect.control.method.fg.ds_zbl",
      FT_UINT8, BASE_DEC, VALS(ect_ds_zbl_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_bg_tlv,
    {"TLV", "docsis_ect.control.method.bg.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_bg_tlv_type,
    {"Type", "docsis_ect.control.method.bg.tlv.type",
      FT_UINT8, BASE_DEC, VALS(ect_control_method_bg_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_bg_tlv_length,
    {"Length", "docsis_ect.control.method.bg.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_bg_duration,
    {"Duration", "docsis_ect.control.method.bg.duration",
      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_bg_periodicity,
    {"Periodicity", "docsis_ect.control.method.bg.periodicity",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_bg_expiration_time,
    {"Expiration Time", "docsis_ect.control.method.bg.expiration_time",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_method_bg_start_time,
    {"Start Time", "docsis_ect.control.method.bg.start_time",
      FT_UINT32, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_partial_service_tlv,
    {"TLV", "docsis_ect.control.partial_service.tlv",
      FT_BYTES, BASE_NO_DISPLAY_VALUE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_partial_service_tlv_type,
    {"Type", "docsis_ect.control.partial_service.tlv.type",
      FT_UINT8, BASE_DEC, VALS(ect_control_partial_service_tlv_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_partial_service_tlv_length,
    {"Length", "docsis_ect.control.partial_service.tlv.length",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_partial_service_dcid,
    {"DCID", "docsis_ect.control.partial_service.dcid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_partial_service_ucid,
    {"UCID", "docsis_ect.control.partial_service.ucid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_deferral_time,
    {"Deferral Time", "docsis_ect.control.deferral_time",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(ect_deferral_time_val), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_ect_control_rxmer_duration,
    {"RxMER Duration", "docsis_ect.control.rxmer_duration",
      FT_UINT8, BASE_DEC|BASE_UNIT_STRING, UNS(&units_symbols), 0x0,
      NULL, HFILL}
    },
    /* DPR */
    {&hf_docsis_dpr_carrier,
    {"Carrier DCID", "docsis_dpr.carrier",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpr_dcid,
    {"Protected DCID", "docsis_dpr.dcid",
      FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpr_tg_id,
    {"Protected TG ID", "docsis_dpr.tg_id",
      FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(dpr_tg_id_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpr_reserved,
    {"Reserved", "docsis_dpr.reserved",
      FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL}
    },
    {&hf_docsis_dpr_start_time,
    {"Start time", "docsis_dpr.start_time",
      FT_UINT32, BASE_CUSTOM, CF_FUNC(d30_time_ticks), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_dpr_duration,
    {"Duration", "docsis_dpr.duration",
      FT_UINT32, BASE_CUSTOM, CF_FUNC(d30_time_ticks), 0x0,
      NULL, HFILL}
    },
    /* MAC Management */
    {&hf_docsis_mgt_upstream_chid,
     {"Upstream Channel ID", "docsis_mgmt.upchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_down_chid,
     {"Downstream Channel ID", "docsis_mgmt.downchid",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Management Message", HFILL}
    },
    {&hf_docsis_mgt_tranid,
     {"Transaction ID", "docsis_mgmt.tranid",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_dst_addr,
     {"Destination Address", "docsis_mgmt.dst",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_src_addr,
     {"Source Address", "docsis_mgmt.src",
      FT_ETHER, BASE_NONE, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_msg_len,
     {"Message Length - DSAP to End (Bytes)", "docsis_mgmt.msglen",
      FT_UINT16, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_dsap,
     {"DSAP", "docsis_mgmt.dsap",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Destination SAP", HFILL}
    },
    {&hf_docsis_mgt_ssap,
     {"SSAP", "docsis_mgmt.ssap",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      "Source SAP", HFILL}
    },
    {&hf_docsis_mgt_30_transmit_power,
     {"Upstream Transmit Power, sent to 3.0 CMTS", "docsis_mgmt.30_transmit_power",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(fourth_db), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_31_transmit_power,
     {"Upstream Transmit Power, sent to 3.1 CMTS", "docsis_mgmt.31_transmit_power",
      FT_UINT16, BASE_CUSTOM, CF_FUNC(fourth_db), 0x01FF,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_40_transmit_power,
     {"Upstream Transmit Power, sent to 4.0 CMTS", "docsis_mgmt.40_transmit_power",
      FT_INT16, BASE_CUSTOM, CF_FUNC(fourth_db), 0x01FF,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_control,
     {"Control", "docsis_mgmt.control",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_version,
     {"Version", "docsis_mgmt.version",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_type,
     {"Type", "docsis_mgmt.type",
      FT_UINT8, BASE_DEC, VALS (mgmt_type_vals), 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_rsvd,
     {"Reserved", "docsis_mgmt.rsvd",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_multipart,
     {"Multipart", "docsis_mgmt.multipart",
      FT_UINT8, BASE_HEX, NULL, 0x0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_multipart_number_of_fragments,
     {"Multipart - Number of Fragments", "docsis_mgmt.multipart.number_of_fragments",
      FT_UINT8, BASE_CUSTOM, CF_FUNC(multipart_number_of_fragments), 0xF0,
      NULL, HFILL}
    },
    {&hf_docsis_mgt_multipart_fragment_sequence_number,
     {"Multipart - Fragment Sequence Number", "docsis_mgmt.multipart.fragment_sequence_number",
      FT_UINT8, BASE_DEC, NULL, 0x0F,
      NULL, HFILL}
    },
    { &hf_docsis_tlv_fragment_overlap,
     { "Fragment overlap", "docsis_mgmt.tlv.fragment.overlap",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment overlaps with other fragments", HFILL}
    },
    { &hf_docsis_tlv_fragment_overlap_conflict,
     { "Conflicting data in fragment overlap", "docsis_mgmt.tlv.fragment.overlap.conflict",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Overlapping fragments contained conflicting data", HFILL}
    },
    { &hf_docsis_tlv_fragment_multiple_tails,
     { "Multiple tail fragments found", "docsis_mgmt.tlv.fragment.multipletails",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Several tails were found when defragmenting the packet", HFILL}
    },
    { &hf_docsis_tlv_fragment_too_long_fragment,
     { "Fragment too long", "docsis_mgmt.tlv.fragment.toolongfragment",
       FT_BOOLEAN, BASE_NONE, NULL, 0x0,
       "Fragment contained data past end of packet", HFILL}
    },
    { &hf_docsis_tlv_fragment_error,
     { "Defragmentation error", "docsis_mgmt.tlv.fragment.error",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "Defragmentation error due to illegal fragments", HFILL}
    },
    { &hf_docsis_tlv_fragment_count,
     { "Fragment count", "docsis_mgmt.tlv.fragment.count",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_tlv_fragment,
     { "TLV Fragment", "docsis_mgmt.tlv.fragment",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_tlv_fragments,
     { "TLV Fragments", "docsis_mgmt.tlv.fragments",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
    { &hf_docsis_tlv_reassembled_in,
     { "Reassembled TLV in frame", "docsis_mgmt.tlv.reassembled_in",
       FT_FRAMENUM, BASE_NONE, NULL, 0x0,
       "This TLV packet is reassembled in this frame", HFILL}
    },
    { &hf_docsis_tlv_reassembled_length,
     { "Reassembled TLV length", "docsis_mgmt.tlv.reassembled.length",
       FT_UINT32, BASE_DEC, NULL, 0x0,
       "The total length of the reassembled payload", HFILL}
    },
    { &hf_docsis_tlv_reassembled_data,
     { "Reassembled TLV data", "docsis_mgmt.tlv.reassembled.data",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       "The reassembled payload", HFILL}
    },
    { &hf_docsis_tlv_reassembled,
     { "Reassembled TLV", "docsis_mgmt.tlv.reassembled",
       FT_BYTES, BASE_NONE, NULL, 0x0,
       NULL, HFILL}
    },
  };

  static int *ett[] = {
    &ett_docsis_sync,
    &ett_docsis_ucd,
    &ett_docsis_tlv,
    &ett_docsis_burst_tlv,
    &ett_docsis_map,
    &ett_docsis_map_ie,
    &ett_docsis_map_probe_ie,
    &ett_docsis_rngreq,
    &ett_docsis_rngrsp,
    &ett_docsis_rngrsptlv,
    &ett_docsis_rngrsp_tlv_transmit_equalization_encodings,
    &ett_docsis_rngrsp_tlv_transmit_equalization_encodings_coef,
    &ett_docsis_rngrsp_tlv_commanded_power,
    &ett_docsis_rngrsp_tlv_commanded_power_subtlv,
    &ett_docsis_regreq,
    &ett_docsis_regrsp,
    &ett_docsis_uccreq,
    &ett_docsis_uccrsp,
    &ett_docsis_bpkmreq,
    &ett_docsis_bpkmrsp,
    &ett_docsis_bpkmattr,
    &ett_docsis_bpkmattr_tlv,
    &ett_docsis_bpkmattr_cmid,
    &ett_docsis_bpkmattr_scap,
    &ett_docsis_bpkmattr_crypto_suite,
    &ett_docsis_bpkmattr_crypto_suite_list,
    &ett_docsis_bpkmattr_allowed_bpi_versions,
    &ett_docsis_bpkmattr_ocsp_responses,
    &ett_docsis_bpkmattr_cmts_designation,
    &ett_docsis_bpkmattr_tekp,
    &ett_docsis_bpkmattr_sadsc,
    &ett_docsis_bpkmattr_saqry,
    &ett_docsis_bpkmattr_dnld,
    &ett_docsis_regack,
    &ett_docsis_dsareq,
    &ett_docsis_dsarsp,
    &ett_docsis_dsaack,
    &ett_docsis_dscreq,
    &ett_docsis_dscrsp,
    &ett_docsis_dscack,
    &ett_docsis_dsdreq,
    &ett_docsis_dsdrsp,
    &ett_docsis_dccreq,
    &ett_docsis_dccreq_sf_sub,
    &ett_docsis_dccreq_ds_params,
    &ett_docsis_dccreq_tlv,
    &ett_docsis_dccrsp,
    &ett_docsis_dccrsp_cm_jump_time,
    &ett_docsis_dccrsp_tlv,
    &ett_docsis_dccack,
    &ett_docsis_dccack_tlv,
    &ett_docsis_intrngreq,
    &ett_docsis_dcd,
    &ett_docsis_dcd_cfr,
    &ett_docsis_dcd_cfr_ip,
    &ett_docsis_dcd_rule,
    &ett_docsis_dcd_clid,
    &ett_docsis_dcd_cfg,
    &ett_docsis_dcd_tlv,
    &ett_docsis_mdd,
    &ett_tlv,
    &ett_sub_tlv,
    &ett_docsis_mdd_cm_status_ev_en_for_docsis31,
    &ett_docsis_mdd_ds_active_channel_list,
    &ett_docsis_mdd_ds_service_group,
    &ett_docsis_mdd_channel_profile_reporting_control,
    &ett_docsis_mdd_ip_init_param,
    &ett_docsis_mdd_up_active_channel_list,
    &ett_docsis_mdd_upstream_active_channel_list_dschids_maps_ucds_dschids,
    &ett_docsis_mdd_cm_status_event_control,
    &ett_docsis_mdd_dsg_da_to_dsid,
    &ett_docsis_mdd_docsis_version,
    &ett_docsis_mdd_docsis_version_tlv,
    &ett_docsis_mdd_diplexer_band_edge,
    &ett_docsis_mdd_advanced_band_plan,
    &ett_docsis_mdd_bpi_plus,
    &ett_docsis_bintrngreq,
    &ett_docsis_dbcreq,
    &ett_docsis_dbcrsp,
    &ett_docsis_dbcack,
    &ett_docsis_dpvreq,
    &ett_docsis_dpvrsp,
    &ett_docsis_cmstatus,
    &ett_docsis_cmstatus_tlv,
    &ett_docsis_cmstatus_tlvtlv,
    &ett_docsis_cmstatus_status_event_tlv,
    &ett_docsis_cmstatus_status_event_tlvtlv,
    &ett_docsis_cmstatusack,
    &ett_docsis_cmctrlreq,
    &ett_docsis_cmctrlreq_tlv,
    &ett_docsis_cmctrlreq_tlvtlv,
    &ett_docsis_cmctrl_tlv_us_event,
    &ett_docsis_cmctrl_tlv_ds_event,
    &ett_docsis_cmctrlrsp,
    &ett_docsis_regreqmp,
    &ett_docsis_regrspmp,
    &ett_docsis_emreq,
    &ett_docsis_emrsp,
    &ett_docsis_emrsp_tlv,
    &ett_docsis_emrsp_tlvtlv,
    &ett_docsis_ocd,
    &ett_docsis_ocd_tlv,
    &ett_docsis_ocd_tlvtlv,
    &ett_docsis_dpd,
    &ett_docsis_dpd_tlv,
    &ett_docsis_dpd_tlvtlv,
    &ett_docsis_dpd_tlv_subcarrier_assignment,
    &ett_docsis_dpd_tlv_subcarrier_assignment_vector,
    &ett_docsis_optreq,
    &ett_docsis_optreq_tlv,
    &ett_docsis_optreq_tlvtlv,
    &ett_docsis_optreq_tlv_rxmer_thresh_params,
    &ett_docsis_optreq_tlv_rxmer_thresh_params_tlv,
    &ett_docsis_optreq_tlv_trigger_definition_params,
    &ett_docsis_optreq_tlv_trigger_definition_params_tlv,
    &ett_docsis_optrsp,
    &ett_docsis_optrsp_tlv,
    &ett_docsis_optrsp_rxmer_tlv,
    &ett_docsis_optrsp_rxmer_subcarrier_tlv,
    &ett_docsis_optrsp_data_cw_tlv,
    &ett_docsis_optrsp_ncp_fields_tlv,
    &ett_docsis_optack,
    &ett_docsis_rba,
    &ett_docsis_rba_control_byte,
    &ett_docsis_cwt_req,
    &ett_docsis_cwt_rsp,
    &ett_docsis_cwt_tlv,
    &ett_docsis_cwt_subtlv,
    &ett_docsis_ect_req,
    &ett_docsis_ect_rsp,
    &ett_docsis_ect_tlv,
    &ett_docsis_ext_rngreq,
    &ett_docsis_dpr,
    &ett_docsis_mgmt,
    &ett_mgmt_pay,
    &ett_docsis_tlv_fragment,
    &ett_docsis_tlv_fragments,
    &ett_docsis_tlv_reassembled
  };

  static ei_register_info ei[] = {
    {&ei_docsis_mgmt_tlvlen_bad, {"docsis_mgmt.tlvlenbad", PI_MALFORMED, PI_ERROR, "Bad TLV length", EXPFILL}},
    {&ei_docsis_mgmt_tlvtype_unknown, { "docsis_mgmt.tlvtypeunknown", PI_PROTOCOL, PI_WARN, "Unknown TLV type", EXPFILL}},
    {&ei_docsis_mgmt_version_unknown, { "docsis_mgmt.versionunknown", PI_PROTOCOL, PI_WARN, "Unknown mac management version", EXPFILL}},
    {&ei_docsis_mgmt_opt_req_trigger_def_measure_duration, { "docsis_mgmt.optreq_trigger_def.wrongduration", PI_PROTOCOL, PI_WARN, "Wrong duration of FDX-triggered OPT-REQ", EXPFILL}},
    {&ei_docsis_cwt_out_of_range, {"docsis_cwt.out_of_range", PI_PROTOCOL, PI_WARN, "CWT value out-of-range", EXPFILL}},
    {&ei_docsis_ect_control_out_of_range, {"docsis_ect.control.out_of_range", PI_PROTOCOL, PI_WARN, "ECT Control value out-of-range", EXPFILL}},
    {&ei_docsis_dpr_out_of_range, {"docsis_dpr.out_of_range", PI_PROTOCOL, PI_WARN, "DPR Duration out-of-range", EXPFILL}}
   };

  expert_module_t* expert_docsis_mgmt;

  proto_docsis_mgmt = proto_register_protocol ("DOCSIS MAC Management", "DOCSIS MAC MGMT", "docsis_mgmt");

  proto_register_field_array (proto_docsis_mgmt, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
  expert_docsis_mgmt = expert_register_protocol(proto_docsis_mgmt);
  expert_register_field_array(expert_docsis_mgmt, ei, array_length(ei));

  docsis_mgmt_dissector_table = register_dissector_table ("docsis_mgmt",
                                                          "DOCSIS MAC Management", proto_docsis_mgmt,
                                                          FT_UINT8, BASE_DEC);

  /* Register MAC Management commands as their own protocols so we can get the name of the option */
  proto_docsis_sync = proto_register_protocol_in_name_only("DOCSIS Synchronisation Message", "SYNC Message", "docsis_sync", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor", "DOCSIS UCD", "docsis_ucd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_map_v1 = proto_register_protocol_in_name_only("DOCSIS Upstream Bandwidth Allocation - version 1", "DOCSIS MAP", "docsis_map", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_map_v5 = proto_register_protocol_in_name_only("DOCSIS Upstream Bandwidth Allocation - version 5", "DOCSIS MAP", "docsis_map", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_rngreq = proto_register_protocol_in_name_only("DOCSIS Range Request Message", "DOCSIS RNG-REQ", "docsis_rngreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_rngrsp = proto_register_protocol_in_name_only("DOCSIS Ranging Response", "DOCSIS RNG-RSP", "docsis_rngrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regreq = proto_register_protocol_in_name_only("DOCSIS Registration Requests", "DOCSIS REG-REQ", "docsis_regreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regrsp = proto_register_protocol_in_name_only("DOCSIS Registration Responses", "DOCSIS REG-RSP", "docsis_regrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_uccreq = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Change Request", "DOCSIS UCC-REQ", "docsis_uccreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_uccrsp = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Change Response", "DOCSIS UCC-RSP", "docsis_uccrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_bpkmreq = proto_register_protocol_in_name_only("DOCSIS Baseline Privacy Key Management Request", "DOCSIS BPKM-REQ", "docsis_bpkm.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_bpkmrsp = proto_register_protocol_in_name_only("DOCSIS Baseline Privacy Key Management Response", "DOCSIS BPKM-RSP", "docsis_bpkm.rsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regack = proto_register_protocol_in_name_only("DOCSIS Registration Acknowledge", "DOCSIS REG-ACK", "docsis_regack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsareq = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Addition Request", "DOCSIS DSA-REQ", "docsis_dsareq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsarsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Addition Response", "DOCSIS DSA-RSP", "docsis_dsarsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsaack = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Addition Acknowledge", "DOCSIS DSA-ACK", "docsis_dsaack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dscreq = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Change Request", "DOCSIS DSC-REQ", "docsis_dscreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dscrsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Change Response", "DOCSIS DSC-RSP", "docsis_dscrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dscack = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Change Acknowledge", "DOCSIS DSC-ACK", "docsis_dscack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsdreq = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Delete Request", "DOCSIS DSD-REQ", "docsis_dsdreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dsdrsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Service Delete Response", "DOCSIS DSD-RSP", "docsis_dsdrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dccreq = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Change Request", "DOCSIS DCC-REQ", "docsis_dccreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dccrsp = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Change Response", "DOCSIS DCC-RSP", "docsis_dccrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dccack = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Change Acknowledge", "DOCSIS DCC-ACK", "docsis_dccack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_type29ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor Type 29", "DOCSIS type29ucd", "docsis_type29ucd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_intrngreq = proto_register_protocol_in_name_only("DOCSIS Initial Ranging Message", "DOCSIS INT-RNG-REQ", "docsis_intrngreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dcd = proto_register_protocol_in_name_only("DOCSIS Downstream Channel Descriptor", "DOCSIS DCD", "docsis_dcd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_mdd = proto_register_protocol_in_name_only("DOCSIS MAC Domain Description", "DOCSIS MDD", "docsis_mdd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_bintrngreq = proto_register_protocol_in_name_only("DOCSIS Bonded Initial Ranging Message", "DOCSIS B-INT-RNG-REQ", "docsis_bintrngreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_type35ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor Type 35", "DOCSIS type35ucd", "docsis_type35ucd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dbcreq = proto_register_protocol_in_name_only("DOCSIS Dynamic Bonding Change Request", "DOCSIS DBC-REQ", "docsis_dbcreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dbcrsp = proto_register_protocol_in_name_only("DOCSIS Dynamic Bonding Change Response", "DOCSIS DBC-RSP", "docsis_dbcrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dbcack = proto_register_protocol_in_name_only("DOCSIS Dynamic Bonding Change Acknowledge", "DOCSIS DBC-ACK", "docsis_dbcack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dpvreq = proto_register_protocol_in_name_only("DOCSIS Path Verify Request", "DOCSIS DPV-REQ", "docsis_dpv.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dpvrsp = proto_register_protocol_in_name_only("DOCSIS Path Verify Response", "DOCSIS DPV-RSP", "docsis_dpv.rsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cmstatus = proto_register_protocol_in_name_only("DOCSIS CM-STATUS Report", "DOCSIS CM-STATUS", "docsis_cmstatus", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cmstatusack = proto_register_protocol_in_name_only("DOCSIS Status Report Acknowledge", "DOCSIS CM-STATUS-ACK", "docsis_cmstatusack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cmctrlreq = proto_register_protocol_in_name_only("DOCSIS CM Control Request", "DOCSIS CM-CTRL-REQ", "docsis_cmctrl.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cmctrlrsp = proto_register_protocol_in_name_only("DOCSIS CM Control Response", "DOCSIS CM-CTRL-RSP", "docsis_cmctrlrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regreqmp = proto_register_protocol_in_name_only("DOCSIS Registration Request Multipart", "DOCSIS Reg-Req-Mp", "docsis_regreqmp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_regrspmp = proto_register_protocol_in_name_only("DOCSIS Registration Response Multipart", "DOCSIS Reg-Rsp-Mp", "docsis_regrspmp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_emreq = proto_register_protocol_in_name_only("DOCSIS Energy Management Request", "DOCSIS EM-REQ", "docsis_emreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_emrsp = proto_register_protocol_in_name_only("DOCSIS Energy Management Response", "DOCSIS EM-RSP", "docsis_emrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_ocd = proto_register_protocol_in_name_only("DOCSIS OFDM Channel Descriptor", "DOCSIS OCD", "docsis_ocd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dpd = proto_register_protocol_in_name_only("DOCSIS Downstream Profile Descriptor", "DOCSIS DPD", "docsis_dpd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_type51ucd = proto_register_protocol_in_name_only("DOCSIS Upstream Channel Descriptor Type 51", "DOCSIS type51ucd", "docsis_type51ucd", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_optreq = proto_register_protocol_in_name_only("OFDM Downstream Profile Test Request", "DOCSIS OPT-REQ", "docsis_optreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_optrsp = proto_register_protocol_in_name_only("OFDM Downstream Profile Test Response", "DOCSIS OPT-RSP", "docsis_optrsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_optack = proto_register_protocol_in_name_only("OFDM Downstream Profile Test Acknowledge", "DOCSIS OPT-ACK", "docsis_optack", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_rba = proto_register_protocol_in_name_only("DOCSIS Resource Block Assignment Message", "DOCSIS RBA", "docsis_rba", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cwt_req = proto_register_protocol_in_name_only("DOCSIS IG Discovery CW Test Request", "DOCSIS CWT-REQ", "docsis_cwt.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_cwt_rsp = proto_register_protocol_in_name_only("DOCSIS IG Discovery CW Test Response", "DOCSIS CWT-RSP", "docsis_cwt.rsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_ect_req = proto_register_protocol_in_name_only("DOCSIS CM Echo Cancellation Training Request", "DOCSIS ECT-REQ", "docsis_ect.req", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_ect_rsp = proto_register_protocol_in_name_only("DOCSIS CM Echo Cancellation Training Response", "DOCSIS ECT-RSP", "docsis_ect.rsp", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_ext_rngreq = proto_register_protocol_in_name_only("DOCSIS Extended Range Request Message", "DOCSIS EXT-RNG-REQ", "docsis_ext_rngreq", proto_docsis_mgmt, FT_BYTES);
  proto_docsis_dpr = proto_register_protocol_in_name_only("DOCSIS Downstream Protection", "DOCSIS DPR", "docsis_dpr", proto_docsis_mgmt, FT_BYTES);

  register_dissector ("docsis_mgmt", dissect_macmgmt, proto_docsis_mgmt);
  docsis_ucd_handle = register_dissector ("docsis_ucd", dissect_ucd, proto_docsis_ucd);
  docsis_rba_handle = register_dissector ("docsis_rba", dissect_rba, proto_docsis_rba);
}

void
proto_reg_handoff_docsis_mgmt (void)
{
  /* Create dissection function handles for all MAC Management commands */
  dissector_add_uint ("docsis_mgmt", MGT_SYNC, create_dissector_handle( dissect_sync, proto_docsis_sync ));
  dissector_add_uint ("docsis_mgmt", MGT_UCD, docsis_ucd_handle);
  dissector_add_uint ("docsis_mgmt", 256*MAP_v1 + MGT_MAP, create_dissector_handle( dissect_map_v1, proto_docsis_map_v1 ));
  dissector_add_uint ("docsis_mgmt", 256*MAP_v5 + MGT_MAP, create_dissector_handle( dissect_map_v5, proto_docsis_map_v5 ));
  dissector_add_uint ("docsis_mgmt", MGT_RNG_REQ, create_dissector_handle( dissect_rngreq, proto_docsis_rngreq ));
  dissector_add_uint ("docsis_mgmt", MGT_RNG_RSP, create_dissector_handle( dissect_rngrsp, proto_docsis_rngrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_REQ, create_dissector_handle( dissect_regreq, proto_docsis_regreq ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_RSP, create_dissector_handle( dissect_regrsp, proto_docsis_regrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_UCC_REQ, create_dissector_handle( dissect_uccreq, proto_docsis_uccreq ));
  dissector_add_uint ("docsis_mgmt", MGT_UCC_RSP, create_dissector_handle( dissect_uccrsp, proto_docsis_uccrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_BPKM_REQ, create_dissector_handle( dissect_bpkmreq, proto_docsis_bpkmreq ));
  dissector_add_uint ("docsis_mgmt", MGT_BPKM_RSP, create_dissector_handle( dissect_bpkmrsp, proto_docsis_bpkmrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_ACK, create_dissector_handle( dissect_regack, proto_docsis_regack ));
  dissector_add_uint ("docsis_mgmt", MGT_DSA_REQ, create_dissector_handle( dissect_dsareq, proto_docsis_dsareq ));
  dissector_add_uint ("docsis_mgmt", MGT_DSA_RSP, create_dissector_handle( dissect_dsarsp, proto_docsis_dsarsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DSA_ACK, create_dissector_handle( dissect_dsaack, proto_docsis_dsaack ));
  dissector_add_uint ("docsis_mgmt", MGT_DSC_REQ, create_dissector_handle( dissect_dscreq, proto_docsis_dscreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DSC_RSP, create_dissector_handle( dissect_dscrsp, proto_docsis_dscrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DSC_ACK, create_dissector_handle( dissect_dscack, proto_docsis_dscack ));
  dissector_add_uint ("docsis_mgmt", MGT_DSD_REQ, create_dissector_handle( dissect_dsdreq, proto_docsis_dsdreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DSD_RSP, create_dissector_handle( dissect_dsdrsp, proto_docsis_dsdrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DCC_REQ, create_dissector_handle( dissect_dccreq, proto_docsis_dccreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DCC_RSP, create_dissector_handle( dissect_dccrsp, proto_docsis_dccrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DCC_ACK, create_dissector_handle( dissect_dccack, proto_docsis_dccack ));
  dissector_add_uint ("docsis_mgmt", MGT_TYPE29UCD, create_dissector_handle( dissect_type29ucd, proto_docsis_type29ucd ));
  dissector_add_uint ("docsis_mgmt", MGT_INIT_RNG_REQ, create_dissector_handle( dissect_intrngreq, proto_docsis_intrngreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DS_CH_DESC, create_dissector_handle( dissect_dcd, proto_docsis_dcd ));
  dissector_add_uint ("docsis_mgmt", MGT_MDD, create_dissector_handle( dissect_mdd, proto_docsis_mdd ));
  dissector_add_uint ("docsis_mgmt", MGT_B_INIT_RNG_REQ, create_dissector_handle( dissect_bintrngreq, proto_docsis_bintrngreq ));
  dissector_add_uint ("docsis_mgmt", MGT_TYPE35UCD, create_dissector_handle( dissect_type35ucd, proto_docsis_type35ucd ));
  dissector_add_uint ("docsis_mgmt", MGT_DBC_REQ, create_dissector_handle( dissect_dbcreq, proto_docsis_dbcreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DBC_RSP, create_dissector_handle( dissect_dbcrsp, proto_docsis_dbcrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_DBC_ACK, create_dissector_handle( dissect_dbcack, proto_docsis_dbcack ));
  dissector_add_uint ("docsis_mgmt", MGT_DPV_REQ, create_dissector_handle( dissect_dpvreq, proto_docsis_dpvreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DPV_RSP, create_dissector_handle( dissect_dpvrsp, proto_docsis_dpvrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_CM_STATUS, create_dissector_handle( dissect_cmstatus, proto_docsis_cmstatus ));
  dissector_add_uint ("docsis_mgmt", MGT_CM_STATUS_ACK, create_dissector_handle( dissect_cmstatusack, proto_docsis_cmstatusack ));
  dissector_add_uint ("docsis_mgmt", MGT_CM_CTRL_REQ, create_dissector_handle( dissect_cmctrlreq, proto_docsis_cmctrlreq ));
  dissector_add_uint ("docsis_mgmt", MGT_CM_CTRL_RSP, create_dissector_handle( dissect_cmctrlrsp, proto_docsis_cmctrlrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_REQ_MP, create_dissector_handle( dissect_regreqmp, proto_docsis_regreqmp ));
  dissector_add_uint ("docsis_mgmt", MGT_REG_RSP_MP, create_dissector_handle( dissect_regrspmp, proto_docsis_regrspmp ));
  dissector_add_uint ("docsis_mgmt", MGT_EM_REQ, create_dissector_handle( dissect_emreq, proto_docsis_emreq ));
  dissector_add_uint ("docsis_mgmt", MGT_EM_RSP, create_dissector_handle( dissect_emrsp, proto_docsis_emrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_OCD, create_dissector_handle( dissect_ocd, proto_docsis_ocd ));
  dissector_add_uint ("docsis_mgmt", MGT_DPD, create_dissector_handle( dissect_dpd, proto_docsis_dpd ));
  dissector_add_uint ("docsis_mgmt", MGT_TYPE51UCD, create_dissector_handle( dissect_type51ucd, proto_docsis_type51ucd ));
  dissector_add_uint ("docsis_mgmt", MGT_OPT_REQ, create_dissector_handle( dissect_optreq, proto_docsis_optreq ));
  dissector_add_uint ("docsis_mgmt", MGT_OPT_RSP, create_dissector_handle( dissect_optrsp, proto_docsis_optrsp ));
  dissector_add_uint ("docsis_mgmt", MGT_OPT_ACK, create_dissector_handle( dissect_optack, proto_docsis_optack ));
  dissector_add_uint ("docsis_mgmt", MGT_RBA_SW, docsis_rba_handle);
  dissector_add_uint ("docsis_mgmt", MGT_RBA_HW, docsis_rba_handle);
  dissector_add_uint ("docsis_mgmt", MGT_CWT_REQ, create_dissector_handle(dissect_cwt_req, proto_docsis_cwt_req));
  dissector_add_uint ("docsis_mgmt", MGT_CWT_RSP, create_dissector_handle(dissect_cwt_rsp, proto_docsis_cwt_rsp));
  dissector_add_uint ("docsis_mgmt", MGT_ECT_REQ, create_dissector_handle(dissect_ect_req, proto_docsis_ect_req));
  dissector_add_uint ("docsis_mgmt", MGT_ECT_RSP, create_dissector_handle(dissect_ect_rsp, proto_docsis_ect_rsp));
  dissector_add_uint ("docsis_mgmt", MGT_EXT_RNG_REQ, create_dissector_handle( dissect_ext_rngreq, proto_docsis_ext_rngreq ));
  dissector_add_uint ("docsis_mgmt", MGT_DPR, create_dissector_handle(dissect_dpr, proto_docsis_dpr));
  dissector_add_uint ("docsis_mgmt", MGT_BPKM_REQ_V5, create_dissector_handle(dissect_bpkmreq, proto_docsis_bpkmreq));
  dissector_add_uint ("docsis_mgmt", MGT_BPKM_RSP_V5, create_dissector_handle(dissect_bpkmrsp, proto_docsis_bpkmrsp));

  docsis_tlv_handle = find_dissector ("docsis_tlv");

  reassembly_table_register(&docsis_tlv_reassembly_table, &addresses_reassembly_table_functions);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */

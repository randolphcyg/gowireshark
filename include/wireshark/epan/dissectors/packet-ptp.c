/* packet-ptp.c
 * Routines for PTP (Precision Time Protocol) dissection
 * Copyright 2004, Auges Tchouante <tchouante2001@yahoo.fr>
 * Copyright 2004, Dominic Bechaz <bdo@zhwin.ch> , ZHW/InES
 * Copyright 2004, Markus Seehofer <mseehofe@nt.hirschmann.de>
 * Copyright 2006, Christian Schaer <scc@zhwin.ch>
 * Copyright 2007, Markus Renz <Markus.Renz@hirschmann.de>
 * Copyright 2010, Torrey Atcitty <torrey.atcitty@harman.com>
 *                 Dave Olsen <dave.olsen@harman.com>
 * Copyright 2013, Andreas Bachmann <bacr@zhaw.ch>, ZHAW/InES
 * Copyright 2016, Uli Heilmeier <uh@heilmeier.eu>
 * Copyright 2017, Adam Wujek <adam.wujek@cern.ch>
 * Copyright 2022, Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2023, Adam Wujek <dev_public@wujek.eu> for CERN
 * Copyright 2024, Patrik Thunström <patrik.thunstroem@technica-engineering.de>
 *
 * Revisions:
 * - Markus Seehofer 09.08.2005 <mseehofe@nt.hirschmann.de>
 *   - Included the "startingBoundaryHops" field in
 *     ptp_management messages.
 * - Christian Schaer 07.07.2006 <scc@zhwin.ch>
 *   - Added support for PTP version 2
 * - Markus Renz 2007-06-01
 *   - updated support for PTPv2
 * - Markus Renz added Management for PTPv2, update to Draft 2.2
 * - Torrey Atcitty & Dave Olsen 05.14.2010
 *   - Added support for 802.1AS D7.0
 * - Andreas Bachmann 08.07.2013 <bacr@zhaw.ch>
 *   - allow multiple TLVs
 *   - bugfix in logInterMessagePeriod uint8_t -> int8_t
 * - Uli Heilmeier 21.03.2016 <uh@heilmeier.eu>
 *   - Added support for SMPTE TLV
 * - Adam Wujek 17.10.2017 <adam.wujek@cern.ch>
 *   - Added support for White Rabbit TLV
 * - Prashant Tripathi 19-02-2021 <prashant_tripathi@selinc.com>
 *   - Added support for C37.238-2017
 * - Dr. Lars Voelker 05-01-2022 <lars.voelker@technica-engineering.de>
 *   - Added analysis support
 * - Adam Wujek 28.08.2023 <dev_public@wujek.eu>
 *   - Added support for L1Sync
 * - Patrik Thunström 27.01.2024 <patrik.thunstroem@technica-engineering.de>
 *   - Improvements/corrections for cumulativeScaledRateOffset
 * - Prashant Tripathi 31-07-2024 <prashant_tripathi@selinc.com>
 *   - Corrections to timeOfNextJump field in ATOI TLV

 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>
#include <locale.h>

#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/oui.h>
#include <epan/addr_resolv.h>
#include "packet-ptp.h"

#define NS_PER_S 1000000000

/**********************************************************/
/* Port definition's for PTP                              */
/**********************************************************/
#define PTP_PORT_RANGE      "319-320"

/* END Port definition's for PTP */
void proto_register_ptp(void);
void proto_reg_handoff_ptp(void);

static int proto_ptp;
/* To keep the decimal point based on locale */
static char * decimal_point;

/***********************************************************************************/
/* Definitions and fields for PTPv1 dissection.                                    */
/***********************************************************************************/


/**********************************************************/
/* Offsets of fields within a PTPv1 packet.               */
/**********************************************************/

/* Common offsets for all Messages (Synch, Delay_Req, Follow_Up, Delay_Resp ....) */
#define PTP_VERSIONPTP_OFFSET                        0
#define PTP_VERSIONNETWORK_OFFSET                    2
#define PTP_SUBDOMAIN_OFFSET                         4
#define PTP_MESSAGETYPE_OFFSET                      20
#define PTP_SOURCECOMMUNICATIONTECHNOLOGY_OFFSET    21
#define PTP_SOURCEUUID_OFFSET                       22
#define PTP_SOURCEPORTID_OFFSET                     28
#define PTP_SEQUENCEID_OFFSET                       30
#define PTP_CONTROLFIELD_OFFSET                     32
#define PTP_FLAGS_OFFSET                            34
#define PTP_FLAGS_LI61_OFFSET                       34
#define PTP_FLAGS_LI59_OFFSET                       34
#define PTP_FLAGS_BOUNDARY_CLOCK_OFFSET             34
#define PTP_FLAGS_ASSIST_OFFSET                     34
#define PTP_FLAGS_EXT_SYNC_OFFSET                   34
#define PTP_FLAGS_PARENT_STATS_OFFSET               34
#define PTP_FLAGS_SYNC_BURST_OFFSET                 34

/* Offsets for PTP_Sync and Delay_Req (=SDR) messages */
#define PTP_SDR_ORIGINTIMESTAMP_OFFSET                       40
#define PTP_SDR_ORIGINTIMESTAMP_SECONDS_OFFSET               40
#define PTP_SDR_ORIGINTIMESTAMP_NANOSECONDS_OFFSET           44
#define PTP_SDR_EPOCHNUMBER_OFFSET                           48
#define PTP_SDR_CURRENTUTCOFFSET_OFFSET                      50
#define PTP_SDR_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET    53
#define PTP_SDR_GRANDMASTERCLOCKUUID_OFFSET                  54
#define PTP_SDR_GRANDMASTERPORTID_OFFSET                     60
#define PTP_SDR_GRANDMASTERSEQUENCEID_OFFSET                 62
#define PTP_SDR_GRANDMASTERCLOCKSTRATUM_OFFSET               67
#define PTP_SDR_GRANDMASTERCLOCKIDENTIFIER_OFFSET            68
#define PTP_SDR_GRANDMASTERCLOCKVARIANCE_OFFSET              74
#define PTP_SDR_GRANDMASTERPREFERRED_OFFSET                  77
#define PTP_SDR_GRANDMASTERISBOUNDARYCLOCK_OFFSET            79
#define PTP_SDR_SYNCINTERVAL_OFFSET                          83
#define PTP_SDR_LOCALCLOCKVARIANCE_OFFSET                    86
#define PTP_SDR_LOCALSTEPSREMOVED_OFFSET                     90
#define PTP_SDR_LOCALCLOCKSTRATUM_OFFSET                     95
#define PTP_SDR_LOCALCLOCKIDENTIFIER_OFFSET                  96
#define PTP_SDR_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET        101
#define PTP_SDR_PARENTUUID_OFFSET                           102
#define PTP_SDR_PARENTPORTFIELD_OFFSET                      110
#define PTP_SDR_ESTIMATEDMASTERVARIANCE_OFFSET              114
#define PTP_SDR_ESTIMATEDMASTERDRIFT_OFFSET                 116
#define PTP_SDR_UTCREASONABLE_OFFSET                        123

/* Offsets for Follow_Up (=FU) messages */
#define PTP_FU_ASSOCIATEDSEQUENCEID_OFFSET                   42
#define PTP_FU_PRECISEORIGINTIMESTAMP_OFFSET                 44
#define PTP_FU_PRECISEORIGINTIMESTAMP_SECONDS_OFFSET         44
#define PTP_FU_PRECISEORIGINTIMESTAMP_NANOSECONDS_OFFSET     48

/* Offsets for Delay_Resp (=DR) messages */
#define PTP_DR_DELAYRECEIPTTIMESTAMP_OFFSET                     40
#define PTP_DR_DELAYRECEIPTTIMESTAMP_SECONDS_OFFSET             40
#define PTP_DR_DELAYRECEIPTTIMESTAMP_NANOSECONDS_OFFSET         44
#define PTP_DR_REQUESTINGSOURCECOMMUNICATIONTECHNOLOGY_OFFSET   49
#define PTP_DR_REQUESTINGSOURCEUUID_OFFSET                      50
#define PTP_DR_REQUESTINGSOURCEPORTID_OFFSET                    56
#define PTP_DR_REQUESTINGSOURCESEQUENCEID_OFFSET                58

/* Offsets for Management (=MM) messages */
#define PTP_MM_TARGETCOMMUNICATIONTECHNOLOGY_OFFSET             41
#define PTP_MM_TARGETUUID_OFFSET                                42
#define PTP_MM_TARGETPORTID_OFFSET                              48
#define PTP_MM_STARTINGBOUNDARYHOPS_OFFSET                      50
#define PTP_MM_BOUNDARYHOPS_OFFSET                              52
#define PTP_MM_MANAGEMENTMESSAGEKEY_OFFSET                      55
#define PTP_MM_PARAMETERLENGTH_OFFSET                           58

    /* PARAMETERLENGTH > 0 */
#define PTP_MM_MESSAGEPARAMETERS_OFFSET                         60

    /* PTP_MM_CLOCK_IDENTITY (PARAMETERLENGTH = 64) */
#define PTP_MM_CLOCK_IDENTITY_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET    63
#define PTP_MM_CLOCK_IDENTITY_CLOCKUUIDFIELD_OFFSET                  64
#define PTP_MM_CLOCK_IDENTITY_CLOCKPORTFIELD_OFFSET                  74
#define PTP_MM_CLOCK_IDENTITY_MANUFACTURERIDENTITY_OFFSET            76

    /* PTP_MM_INITIALIZE_CLOCK (PARAMETERLENGTH = 4) */
#define PTP_MM_INITIALIZE_CLOCK_INITIALISATIONKEY_OFFSET             62

    /* PTP_MM_SET_SUBDOMAIN (PARAMETERLENGTH = 16) */
#define PTP_MM_SET_SUBDOMAIN_SUBDOMAINNAME_OFFSET                    60

    /* PTP_MM_DEFAULT_DATA_SET (PARAMETERLENGTH = 76) */
#define PTP_MM_DEFAULT_DATA_SET_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET  63
#define PTP_MM_DEFAULT_DATA_SET_CLOCKUUIDFIELD_OFFSET                64
#define PTP_MM_DEFAULT_DATA_SET_CLOCKPORTFIELD_OFFSET                74
#define PTP_MM_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET                  79
#define PTP_MM_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET               80
#define PTP_MM_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET                 86
#define PTP_MM_DEFAULT_DATA_SET_CLOCKFOLLOWUPCAPABLE_OFFSET          89
#define PTP_MM_DEFAULT_DATA_SET_PREFERRED_OFFSET                     95
#define PTP_MM_DEFAULT_DATA_SET_INITIALIZABLE_OFFSET                 99
#define PTP_MM_DEFAULT_DATA_SET_EXTERNALTIMING_OFFSET               103
#define PTP_MM_DEFAULT_DATA_SET_ISBOUNDARYCLOCK_OFFSET              107
#define PTP_MM_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET                 111
#define PTP_MM_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET                112
#define PTP_MM_DEFAULT_DATA_SET_NUMBERPORTS_OFFSET                  130
#define PTP_MM_DEFAULT_DATA_SET_NUMBERFOREIGNRECORDS_OFFSET         134

    /* PTP_MM_UPDATE_DEFAULT_DATA_SET (PARAMETERLENGTH = 36) */
#define PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET           63
#define PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET        64
#define PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET          70
#define PTP_MM_UPDATE_DEFAULT_DATA_SET_PREFERRED_OFFSET              75
#define PTP_MM_UPDATE_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET           79
#define PTP_MM_UPDATE_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET          80

    /* PTP_MM_CURRENT_DATA_SET (PARAMETERLENGTH = 20) */
#define PTP_MM_CURRENT_DATA_SET_STEPSREMOVED_OFFSET                  62
#define PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTER_OFFSET              64
#define PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERSECONDS_OFFSET       64
#define PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERNANOSECONDS_OFFSET   68
#define PTP_MM_CURRENT_DATA_SET_ONEWAYDELAY_OFFSET                   72
#define PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYSECONDS_OFFSET            72
#define PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYNANOSECONDS_OFFSET        76

    /* PTP_MM_PARENT_DATA_SET (PARAMETERLENGTH = 90) */
#define PTP_MM_PARENT_DATA_SET_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET  63
#define PTP_MM_PARENT_DATA_SET_PARENTUUID_OFFSET                     64
#define PTP_MM_PARENT_DATA_SET_PARENTPORTID_OFFSET                   74
#define PTP_MM_PARENT_DATA_SET_PARENTLASTSYNCSEQUENCENUMBER_OFFSET   78
#define PTP_MM_PARENT_DATA_SET_PARENTFOLLOWUPCAPABLE_OFFSET          83
#define PTP_MM_PARENT_DATA_SET_PARENTEXTERNALTIMING_OFFSET           87
#define PTP_MM_PARENT_DATA_SET_PARENTVARIANCE_OFFSET                 90
#define PTP_MM_PARENT_DATA_SET_PARENTSTATS_OFFSET                    95
#define PTP_MM_PARENT_DATA_SET_OBSERVEDVARIANCE_OFFSET               98
#define PTP_MM_PARENT_DATA_SET_OBSERVEDDRIFT_OFFSET                 100
#define PTP_MM_PARENT_DATA_SET_UTCREASONABLE_OFFSET                 107
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET    111
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERUUIDFIELD_OFFSET          112
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERPORTIDFIELD_OFFSET        122
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERSTRATUM_OFFSET            127
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERIDENTIFIER_OFFSET         128
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERVARIANCE_OFFSET           134
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERPREFERRED_OFFSET          139
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERISBOUNDARYCLOCK_OFFSET    143
#define PTP_MM_PARENT_DATA_SET_GRANDMASTERSEQUENCENUMBER_OFFSET     146

    /* PTP_MM_PORT_DATA_SET (PARAMETERLENGTH = 52) */
#define PTP_MM_PORT_DATA_SET_RETURNEDPORTNUMBER_OFFSET               62
#define PTP_MM_PORT_DATA_SET_PORTSTATE_OFFSET                        67
#define PTP_MM_PORT_DATA_SET_LASTSYNCEVENTSEQUENCENUMBER_OFFSET      70
#define PTP_MM_PORT_DATA_SET_LASTGENERALEVENTSEQUENCENUMBER_OFFSET   74
#define PTP_MM_PORT_DATA_SET_PORTCOMMUNICATIONTECHNOLOGY_OFFSET      79
#define PTP_MM_PORT_DATA_SET_PORTUUIDFIELD_OFFSET                    80
#define PTP_MM_PORT_DATA_SET_PORTIDFIELD_OFFSET                      90
#define PTP_MM_PORT_DATA_SET_BURSTENABLED_OFFSET                     95
#define PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESSOCTETS_OFFSET           97
#define PTP_MM_PORT_DATA_SET_EVENTPORTADDRESSOCTETS_OFFSET           98
#define PTP_MM_PORT_DATA_SET_GENERALPORTADDRESSOCTETS_OFFSET         99
#define PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESS_OFFSET                100
#define PTP_MM_PORT_DATA_SET_EVENTPORTADDRESS_OFFSET                106
#define PTP_MM_PORT_DATA_SET_GENERALPORTADDRESS_OFFSET              110

    /* PTP_MM_GLOBAL_TIME_DATA_SET (PARAMETERLENGTH = 24) */
#define PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIME_OFFSET                 60
#define PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMESECONDS_OFFSET          60
#define PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMENANOSECONDS_OFFSET      64
#define PTP_MM_GLOBAL_TIME_DATA_SET_CURRENTUTCOFFSET_OFFSET          70
#define PTP_MM_GLOBAL_TIME_DATA_SET_LEAP59_OFFSET                    75
#define PTP_MM_GLOBAL_TIME_DATA_SET_LEAP61_OFFSET                    79
#define PTP_MM_GLOBAL_TIME_DATA_SET_EPOCHNUMBER_OFFSET               82

    /* PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES (PARAMETERLENGTH = 16) */
#define PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_CURRENTUTCOFFSET_OFFSET 62
#define PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP59_OFFSET           67
#define PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP61_OFFSET           71
#define PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_EPOCHNUMBER_OFFSET      74

    /* PTP_MM_GET_FOREIGN_DATA_SET (PARAMETERLENGTH = 4) */
#define PTP_MM_GET_FOREIGN_DATA_SET_RECORDKEY_OFFSET                 62

    /* PTP_MM_FOREIGN_DATA_SET (PARAMETERLENGTH = 28) */
#define PTP_MM_FOREIGN_DATA_SET_RETURNEDPORTNUMBER_OFFSET            62
#define PTP_MM_FOREIGN_DATA_SET_RETURNEDRECORDNUMBER_OFFSET          66
#define PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERCOMMUNICATIONTECHNOLOGY_OFFSET 71
#define PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERUUIDFIELD_OFFSET        72
#define PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERPORTIDFIELD_OFFSET      82
#define PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERSYNCS_OFFSET            86

    /* PTP_MM_SET_SYNC_INTERVAL (PARAMETERLENGTH = 4) */
#define PTP_MM_SET_SYNC_INTERVAL_SYNCINTERVAL_OFFSET                 62

    /* PTP_MM_SET_TIME (PARAMETERLENGTH = 8) */
#define PTP_MM_SET_TIME_LOCALTIME_OFFSET                             60
#define PTP_MM_SET_TIME_LOCALTIMESECONDS_OFFSET                      60
#define PTP_MM_SET_TIME_LOCALTIMENANOSECONDS_OFFSET                  64

    /* Interface Rate Tlv field offsets */
#define PTP_SIG_TLV_INTERFACE_BIT_PERIOD                             10
#define PTP_SIG_TLV_NUMBERBITS_BEFORE_TIMESTAMP                      18
#define PTP_SIG_TLV_NUMBERBITS_AFTER_TIMESTAMP                       20

/* END Offsets of fields within a PTP packet. */

/**********************************************************/
/* flag-field-mask-definitions                            */
/**********************************************************/
#define PTP_FLAGS_LI61_BITMASK                  0x0001
#define PTP_FLAGS_LI59_BITMASK                  0x0002
#define PTP_FLAGS_BOUNDARY_CLOCK_BITMASK        0x0004
#define PTP_FLAGS_ASSIST_BITMASK                0x0008
#define PTP_FLAGS_EXT_SYNC_BITMASK              0x0010
#define PTP_FLAGS_PARENT_STATS_BITMASK          0x0020
#define PTP_FLAGS_SYNC_BURST_BITMASK            0x0040

/* END flag-field-mask-definitions */

/**********************************************************/
/* managementMessage definitions                          */
/**********************************************************/
#define PTP_MM_NULL                               0
#define PTP_MM_OBTAIN_IDENTITY                    1
#define PTP_MM_CLOCK_IDENTITY                     2
#define PTP_MM_INITIALIZE_CLOCK                   3
#define PTP_MM_SET_SUBDOMAIN                      4
#define PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER  5
#define PTP_MM_SET_DESIGNATED_PREFERRED_MASTER    6
#define PTP_MM_GET_DEFAULT_DATA_SET               7
#define PTP_MM_DEFAULT_DATA_SET                   8
#define PTP_MM_UPDATE_DEFAULT_DATA_SET            9
#define PTP_MM_GET_CURRENT_DATA_SET              10
#define PTP_MM_CURRENT_DATA_SET                  11
#define PTP_MM_GET_PARENT_DATA_SET               12
#define PTP_MM_PARENT_DATA_SET                   13
#define PTP_MM_GET_PORT_DATA_SET                 14
#define PTP_MM_PORT_DATA_SET                     15
#define PTP_MM_GET_GLOBAL_TIME_DATA_SET          16
#define PTP_MM_GLOBAL_TIME_DATA_SET              17
#define PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES     18
#define PTP_MM_GOTO_FAULTY_STATE                 19
#define PTP_MM_GET_FOREIGN_DATA_SET              20
#define PTP_MM_FOREIGN_DATA_SET                  21
#define PTP_MM_SET_SYNC_INTERVAL                 22
#define PTP_MM_DISABLE_PORT                      23
#define PTP_MM_ENABLE_PORT                       24
#define PTP_MM_DISABLE_BURST                     25
#define PTP_MM_ENABLE_BURST                      26
#define PTP_MM_SET_TIME                          27

static const value_string ptp_managementMessageKey_vals[] = {
    {PTP_MM_NULL                              , "PTP_MM_NULL"},
    {PTP_MM_OBTAIN_IDENTITY                   , "PTP_MM_OBTAIN_IDENTITY"},
    {PTP_MM_CLOCK_IDENTITY                    , "PTP_MM_CLOCK_IDENTITY"},
    {PTP_MM_INITIALIZE_CLOCK                  , "PTP_MM_INITIALIZE_CLOCK"},
    {PTP_MM_SET_SUBDOMAIN                     , "PTP_MM_SET_SUBDOMAIN"},
    {PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER , "PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER"},
    {PTP_MM_SET_DESIGNATED_PREFERRED_MASTER   , "PTP_MM_SET_DESIGNATED_PREFERRED_MASTER"},
    {PTP_MM_GET_DEFAULT_DATA_SET              , "PTP_MM_GET_DEFAULT_DATA_SET"},
    {PTP_MM_DEFAULT_DATA_SET                  , "PTP_MM_DEFAULT_DATA_SET"},
    {PTP_MM_UPDATE_DEFAULT_DATA_SET           , "PTP_MM_UPDATE_DEFAULT_DATA_SET"},
    {PTP_MM_GET_CURRENT_DATA_SET              , "PTP_MM_GET_CURRENT_DATA_SET"},
    {PTP_MM_CURRENT_DATA_SET                  , "PTP_MM_CURRENT_DATA_SET"},
    {PTP_MM_GET_PARENT_DATA_SET               , "PTP_MM_GET_PARENT_DATA_SET"},
    {PTP_MM_PARENT_DATA_SET                   , "PTP_MM_PARENT_DATA_SET"},
    {PTP_MM_GET_PORT_DATA_SET                 , "PTP_MM_GET_PORT_DATA_SET"},
    {PTP_MM_PORT_DATA_SET                     , "PTP_MM_PORT_DATA_SET"},
    {PTP_MM_GET_GLOBAL_TIME_DATA_SET          , "PTP_MM_GET_GLOBAL_TIME_DATA_SET"},
    {PTP_MM_GLOBAL_TIME_DATA_SET              , "PTP_MM_GLOBAL_TIME_DATA_SET"},
    {PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES     , "PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES"},
    {PTP_MM_GOTO_FAULTY_STATE                 , "PTP_MM_GOTO_FAULTY_STATE"},
    {PTP_MM_GET_FOREIGN_DATA_SET              , "PTP_MM_GET_FOREIGN_DATA_SET"},
    {PTP_MM_FOREIGN_DATA_SET                  , "PTP_MM_FOREIGN_DATA_SET"},
    {PTP_MM_SET_SYNC_INTERVAL                 , "PTP_MM_SET_SYNC_INTERVAL"},
    {PTP_MM_DISABLE_PORT                      , "PTP_MM_DISABLE_PORT"},
    {PTP_MM_ENABLE_PORT                       , "PTP_MM_ENABLE_PORT"},
    {PTP_MM_DISABLE_BURST                     , "PTP_MM_DISABLE_BURST"},
    {PTP_MM_ENABLE_BURST                      , "PTP_MM_ENABLE_BURST"},
    {PTP_MM_SET_TIME                          , "PTP_MM_SET_TIME"},
    {0,              NULL          }
};
static value_string_ext ptp_managementMessageKey_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_managementMessageKey_vals);

/* same again but better readable text for info column */
static const value_string ptp_managementMessageKey_infocolumn_vals[] = {
    {PTP_MM_NULL                              , "Null"},
    {PTP_MM_OBTAIN_IDENTITY                   , "Obtain Identity"},
    {PTP_MM_CLOCK_IDENTITY                    , "Clock Identity"},
    {PTP_MM_INITIALIZE_CLOCK                  , "Initialize Clock"},
    {PTP_MM_SET_SUBDOMAIN                     , "Set Subdomain"},
    {PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER , "Clear Designated Preferred Master"},
    {PTP_MM_SET_DESIGNATED_PREFERRED_MASTER   , "Set Designated Preferred Master"},
    {PTP_MM_GET_DEFAULT_DATA_SET              , "Get Default Data Set"},
    {PTP_MM_DEFAULT_DATA_SET                  , "Default Data Set"},
    {PTP_MM_UPDATE_DEFAULT_DATA_SET           , "Update Default Data Set"},
    {PTP_MM_GET_CURRENT_DATA_SET              , "Get Current Data Set"},
    {PTP_MM_CURRENT_DATA_SET                  , "Current Data Set"},
    {PTP_MM_GET_PARENT_DATA_SET               , "Get Parent Data Set"},
    {PTP_MM_PARENT_DATA_SET                   , "Parent Data Set"},
    {PTP_MM_GET_PORT_DATA_SET                 , "Get Port Data Set"},
    {PTP_MM_PORT_DATA_SET                     , "Port Data Set"},
    {PTP_MM_GET_GLOBAL_TIME_DATA_SET          , "Get Global Time Data Set"},
    {PTP_MM_GLOBAL_TIME_DATA_SET              , "Global Time Data Set"},
    {PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES     , "Update Global Time Properties"},
    {PTP_MM_GOTO_FAULTY_STATE                 , "Goto Faulty State"},
    {PTP_MM_GET_FOREIGN_DATA_SET              , "Get Foreign Data Set"},
    {PTP_MM_FOREIGN_DATA_SET                  , "Foreign Data Set"},
    {PTP_MM_SET_SYNC_INTERVAL                 , "Set Sync Interval"},
    {PTP_MM_DISABLE_PORT                      , "Disable Port"},
    {PTP_MM_ENABLE_PORT                       , "Enable Port"},
    {PTP_MM_DISABLE_BURST                     , "Disable Burst"},
    {PTP_MM_ENABLE_BURST                      , "Enable Burst"},
    {PTP_MM_SET_TIME                          , "Set Time"},
    {0,              NULL          }
};
static value_string_ext ptp_managementMessageKey_infocolumn_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_managementMessageKey_infocolumn_vals);

/* END managementMessage definitions */

/**********************************************************/
/* CommunicationId definitions                            */
/**********************************************************/
#define PTP_CLOSED                0
#define PTP_ETHER                 1
#define PTP_FFBUS                 4
#define PTP_PROFIBUS              5
#define PTP_LON                   6
#define PTP_DNET                  7
#define PTP_SDS                   8
#define PTP_CONTROLNET            9
#define PTP_CANOPEN              10
#define PTP_IEEE1394            243
#define PTP_IEEE802_11A         244
#define PTP_IEEE_WIRELESS       245
#define PTP_INFINIBAND          246
#define PTP_BLUETOOTH           247
#define PTP_IEEE802_15_1        248
#define PTP_IEEE1451_3          249
#define PTP_IEEE1451_5          250
#define PTP_USB                 251
#define PTP_ISA                 252
#define PTP_PCI                 253
#define PTP_VXI                 254
#define PTP_DEFAULT             255

static const value_string ptp_communicationid_vals[] = {
    {PTP_CLOSED        , "Closed system outside the scope of this standard."},
    {PTP_ETHER         , "IEEE 802.3 (Ethernet)"},
    {PTP_FFBUS         , "FOUNDATION Fieldbus"},
    {PTP_PROFIBUS      , "PROFIBUS"},
    {PTP_LON           , "LonTalk"},
    {PTP_DNET          , "DeviceNet"},
    {PTP_SDS           , "SmartDistributedSystem"},
    {PTP_CONTROLNET    , "ControlNet"},
    {PTP_CANOPEN       , "CANopen"},
    {PTP_IEEE1394      , "IEEE 1394"},
    {PTP_IEEE802_11A   , "IEEE 802.11a"},
    {PTP_IEEE_WIRELESS , "IEEE 802.11b"},
    {PTP_INFINIBAND    , "InfiniBand"},
    {PTP_BLUETOOTH     , "Bluetooth wireless"},
    {PTP_IEEE802_15_1  , "IEEE 802.15.1"},
    {PTP_IEEE1451_3    , "IEEE 1451.3"},
    {PTP_IEEE1451_5    , "IEEE 1451.5"},
    {PTP_USB           , "USB bus"},
    {PTP_ISA           , "ISA bus"},
    {PTP_PCI           , "PCI bus"},
    {PTP_VXI           , "VXI bus"},
    {PTP_DEFAULT       , "Default value"},
    {0,              NULL          }
};
static value_string_ext ptp_communicationid_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_communicationid_vals);

/* END CommunicationId definitions */

/**********************************************************/
/* PTP message types    (PTP_CONTROL field)               */
/**********************************************************/
#define PTP_SYNC_MESSAGE        0x00
#define PTP_DELAY_REQ_MESSAGE   0x01
#define PTP_FOLLOWUP_MESSAGE    0x02
#define PTP_DELAY_RESP_MESSAGE  0x03
#define PTP_MANAGEMENT_MESSAGE  0x04
#define PTP_OTHER_MESSAGE       0x05

static const value_string ptp_controlfield_vals[] = {
    {PTP_SYNC_MESSAGE       , "Sync Message"},
    {PTP_DELAY_REQ_MESSAGE  , "Delay_Req Message"},
    {PTP_FOLLOWUP_MESSAGE   , "Follow_Up Message"},
    {PTP_DELAY_RESP_MESSAGE , "Delay_Resp Message"},
    {PTP_MANAGEMENT_MESSAGE , "Management Message"},
    {PTP_OTHER_MESSAGE      , "Other Message"},
    {0,                       NULL          }
};

/* END PTP message types */

/**********************************************************/
/* Channel values for the PTP_MESSAGETYPE field           */
/**********************************************************/
#define PTP_MESSAGETYPE_EVENT   0x01
#define PTP_MESSAGETYPE_GENERAL 0x02

static const value_string ptp_messagetype_vals[] = {
    {PTP_MESSAGETYPE_EVENT   , "Event Message"},
    {PTP_MESSAGETYPE_GENERAL , "General Message"},
    {0,              NULL          }
};

/* END channel values for the PTP_MESSAGETYPE field */

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/

static int hf_ptp_versionptp;
static int hf_ptp_versionnetwork;
static int hf_ptp_subdomain;
static int hf_ptp_messagetype;
static int hf_ptp_sourcecommunicationtechnology;
static int hf_ptp_sourceuuid;
static int hf_ptp_sourceportid;
static int hf_ptp_sequenceid;
static int hf_ptp_controlfield;
static int hf_ptp_flags;
static int hf_ptp_flags_li61;
static int hf_ptp_flags_li59;
static int hf_ptp_flags_boundary_clock;
static int hf_ptp_flags_assist;
static int hf_ptp_flags_ext_sync;
static int hf_ptp_flags_parent;
static int hf_ptp_flags_sync_burst;

/* Fields for ptp_sync and delay_req (=sdr) messages */
static int hf_ptp_sdr_origintimestamp; /* Field for seconds & nanoseconds */
static int hf_ptp_sdr_origintimestamp_seconds;
static int hf_ptp_sdr_origintimestamp_nanoseconds;
static int hf_ptp_sdr_epochnumber;
static int hf_ptp_sdr_currentutcoffset;
static int hf_ptp_sdr_grandmastercommunicationtechnology;
static int hf_ptp_sdr_grandmasterclockuuid;
static int hf_ptp_sdr_grandmasterportid;
static int hf_ptp_sdr_grandmastersequenceid;
static int hf_ptp_sdr_grandmasterclockstratum;
static int hf_ptp_sdr_grandmasterclockidentifier;
static int hf_ptp_sdr_grandmasterclockvariance;
static int hf_ptp_sdr_grandmasterpreferred;
static int hf_ptp_sdr_grandmasterisboundaryclock;
static int hf_ptp_sdr_syncinterval;
static int hf_ptp_sdr_localclockvariance;
static int hf_ptp_sdr_localstepsremoved;
static int hf_ptp_sdr_localclockstratum;
static int hf_ptp_sdr_localclockidentifier;
static int hf_ptp_sdr_parentcommunicationtechnology;
static int hf_ptp_sdr_parentuuid;
static int hf_ptp_sdr_parentportfield;
static int hf_ptp_sdr_estimatedmastervariance;
static int hf_ptp_sdr_estimatedmasterdrift;
static int hf_ptp_sdr_utcreasonable;

/* Fields for follow_up (=fu) messages */
static int hf_ptp_fu_associatedsequenceid;
static int hf_ptp_fu_preciseorigintimestamp;
static int hf_ptp_fu_preciseorigintimestamp_seconds;
static int hf_ptp_fu_preciseorigintimestamp_nanoseconds;

/* Fields for delay_resp (=dr) messages */
static int hf_ptp_dr_delayreceipttimestamp;
static int hf_ptp_dr_delayreceipttimestamp_seconds;
static int hf_ptp_dr_delayreceipttimestamp_nanoseconds;
static int hf_ptp_dr_requestingsourcecommunicationtechnology;
static int hf_ptp_dr_requestingsourceuuid;
static int hf_ptp_dr_requestingsourceportid;
static int hf_ptp_dr_requestingsourcesequenceid;

/* Fields for management (=mm) messages */
static int hf_ptp_mm_targetcommunicationtechnology;
static int hf_ptp_mm_targetuuid;
static int hf_ptp_mm_targetportid;
static int hf_ptp_mm_startingboundaryhops;
static int hf_ptp_mm_boundaryhops;
static int hf_ptp_mm_managementmessagekey;
static int hf_ptp_mm_parameterlength;
    /* parameterlength > 0 */
/* static int hf_ptp_mm_messageparameters; */
    /* ptp_mm_clock_identity (parameterlength = 64) */
static int hf_ptp_mm_clock_identity_clockcommunicationtechnology;
static int hf_ptp_mm_clock_identity_clockuuidfield;
static int hf_ptp_mm_clock_identity_clockportfield;
static int hf_ptp_mm_clock_identity_manufactureridentity;

    /* ptp_mm_initialize_clock (parameterlength = 4) */
static int hf_ptp_mm_initialize_clock_initialisationkey;

    /* ptp_mm_set_subdomain (parameterlength = 16) */
static int hf_ptp_mm_set_subdomain_subdomainname;

    /* ptp_mm_default_data_set (parameterlength = 76) */
static int hf_ptp_mm_default_data_set_clockcommunicationtechnology;
static int hf_ptp_mm_default_data_set_clockuuidfield;
static int hf_ptp_mm_default_data_set_clockportfield;
static int hf_ptp_mm_default_data_set_clockstratum;
static int hf_ptp_mm_default_data_set_clockidentifier;
static int hf_ptp_mm_default_data_set_clockvariance;
static int hf_ptp_mm_default_data_set_clockfollowupcapable;
static int hf_ptp_mm_default_data_set_preferred;
static int hf_ptp_mm_default_data_set_initializable;
static int hf_ptp_mm_default_data_set_externaltiming;
static int hf_ptp_mm_default_data_set_isboundaryclock;
static int hf_ptp_mm_default_data_set_syncinterval;
static int hf_ptp_mm_default_data_set_subdomainname;
static int hf_ptp_mm_default_data_set_numberports;
static int hf_ptp_mm_default_data_set_numberforeignrecords;

    /* ptp_mm_update_default_data_set (parameterlength = 36) */
static int hf_ptp_mm_update_default_data_set_clockstratum;
static int hf_ptp_mm_update_default_data_set_clockidentifier;
static int hf_ptp_mm_update_default_data_set_clockvariance;
static int hf_ptp_mm_update_default_data_set_preferred;
static int hf_ptp_mm_update_default_data_set_syncinterval;
static int hf_ptp_mm_update_default_data_set_subdomainname;

    /* ptp_mm_current_data_set (parameterlength = 20) */
static int hf_ptp_mm_current_data_set_stepsremoved;
static int hf_ptp_mm_current_data_set_offsetfrommaster;
static int hf_ptp_mm_current_data_set_offsetfrommasterseconds;
static int hf_ptp_mm_current_data_set_offsetfrommasternanoseconds;
static int hf_ptp_mm_current_data_set_onewaydelay;
static int hf_ptp_mm_current_data_set_onewaydelayseconds;
static int hf_ptp_mm_current_data_set_onewaydelaynanoseconds;

    /* ptp_mm_parent_data_set (parameterlength = 90) */
static int hf_ptp_mm_parent_data_set_parentcommunicationtechnology;
static int hf_ptp_mm_parent_data_set_parentuuid;
static int hf_ptp_mm_parent_data_set_parentportid;
static int hf_ptp_mm_parent_data_set_parentlastsyncsequencenumber;
static int hf_ptp_mm_parent_data_set_parentfollowupcapable;
static int hf_ptp_mm_parent_data_set_parentexternaltiming;
static int hf_ptp_mm_parent_data_set_parentvariance;
static int hf_ptp_mm_parent_data_set_parentstats;
static int hf_ptp_mm_parent_data_set_observedvariance;
static int hf_ptp_mm_parent_data_set_observeddrift;
static int hf_ptp_mm_parent_data_set_utcreasonable;
static int hf_ptp_mm_parent_data_set_grandmastercommunicationtechnology;
static int hf_ptp_mm_parent_data_set_grandmasteruuidfield;
static int hf_ptp_mm_parent_data_set_grandmasterportidfield;
static int hf_ptp_mm_parent_data_set_grandmasterstratum;
static int hf_ptp_mm_parent_data_set_grandmasteridentifier;
static int hf_ptp_mm_parent_data_set_grandmastervariance;
static int hf_ptp_mm_parent_data_set_grandmasterpreferred;
static int hf_ptp_mm_parent_data_set_grandmasterisboundaryclock;
static int hf_ptp_mm_parent_data_set_grandmastersequencenumber;

    /* ptp_mm_port_data_set (parameterlength = 52) */
static int hf_ptp_mm_port_data_set_returnedportnumber;
static int hf_ptp_mm_port_data_set_portstate;
static int hf_ptp_mm_port_data_set_lastsynceventsequencenumber;
static int hf_ptp_mm_port_data_set_lastgeneraleventsequencenumber;
static int hf_ptp_mm_port_data_set_portcommunicationtechnology;
static int hf_ptp_mm_port_data_set_portuuidfield;
static int hf_ptp_mm_port_data_set_portidfield;
static int hf_ptp_mm_port_data_set_burstenabled;
static int hf_ptp_mm_port_data_set_subdomainaddressoctets;
static int hf_ptp_mm_port_data_set_eventportaddressoctets;
static int hf_ptp_mm_port_data_set_generalportaddressoctets;
static int hf_ptp_mm_port_data_set_subdomainaddress;
static int hf_ptp_mm_port_data_set_eventportaddress;
static int hf_ptp_mm_port_data_set_generalportaddress;

    /* ptp_mm_global_time_data_set (parameterlength = 24) */
static int hf_ptp_mm_global_time_data_set_localtime;
static int hf_ptp_mm_global_time_data_set_localtimeseconds;
static int hf_ptp_mm_global_time_data_set_localtimenanoseconds;
static int hf_ptp_mm_global_time_data_set_currentutcoffset;
static int hf_ptp_mm_global_time_data_set_leap59;
static int hf_ptp_mm_global_time_data_set_leap61;
static int hf_ptp_mm_global_time_data_set_epochnumber;

    /* ptp_mm_update_global_time_properties (parameterlength = 16) */
static int hf_ptp_mm_update_global_time_properties_currentutcoffset;
static int hf_ptp_mm_update_global_time_properties_leap59;
static int hf_ptp_mm_update_global_time_properties_leap61;
/* static int hf_ptp_mm_update_global_time_properties_epochnumber; */

    /* ptp_mm_get_foreign_data_set (parameterlength = 4) */
static int hf_ptp_mm_get_foreign_data_set_recordkey;

    /* ptp_mm_foreign_data_set (parameterlength = 28) */
static int hf_ptp_mm_foreign_data_set_returnedportnumber;
static int hf_ptp_mm_foreign_data_set_returnedrecordnumber;
static int hf_ptp_mm_foreign_data_set_foreignmastercommunicationtechnology;
static int hf_ptp_mm_foreign_data_set_foreignmasteruuidfield;
static int hf_ptp_mm_foreign_data_set_foreignmasterportidfield;
static int hf_ptp_mm_foreign_data_set_foreignmastersyncs;

    /* ptp_mm_set_sync_interval (parameterlength = 4) */
static int hf_ptp_mm_set_sync_interval_syncinterval;

    /* ptp_mm_set_time (parameterlength = 8) */
static int hf_ptp_mm_set_time_localtime;
static int hf_ptp_mm_set_time_localtimeseconds;
static int hf_ptp_mm_set_time_localtimenanoseconds;

/* END Initialize the protocol and registered fields */

/* Initialize the subtree pointers */
static int ett_ptp;
static int ett_ptp_flags;
static int ett_ptp_time;
static int ett_ptp_time2;

/* END Definitions and fields for PTPv1 dissection. */





/***********************************************************************************/
/* Definitions and fields for PTPv2 dissection.                                    */
/***********************************************************************************/


/**********************************************************/
/* Offsets of fields within a PTPv2 packet.               */
/**********************************************************/

/* Common offsets for all Messages (Sync, Delay_Req, Follow_Up, Delay_Resp ....) */
#define PTP_V2_MAJORSDOID_MESSAGE_TYPE_OFFSET                        0
#define PTP_V2_VERSIONPTP_OFFSET                                     1
#define PTP_V2_MINORVERSIONPTP_OFFSET         PTP_V2_VERSIONPTP_OFFSET
#define PTP_V2_MESSAGE_LENGTH_OFFSET                                 2
#define PTP_V2_DOMAIN_NUMBER_OFFSET                                  4
#define PTP_V2_MINORSDOID_OFFSET                                     5
#define PTP_V2_FLAGS_OFFSET                                          6
#define PTP_V2_CORRECTION_OFFSET                                     8
#define PTP_V2_CORRECTIONNS_OFFSET                                   8
#define PTP_V2_CORRECTIONSUBNS_OFFSET                               14
#define PTP_V2_MESSAGE_TYPE_SPECIFIC_OFFSET                         16
#define PTP_V2_CLOCKIDENTITY_OFFSET                                 20
#define PTP_V2_SOURCEPORTID_OFFSET                                  28
#define PTP_V2_SEQUENCEID_OFFSET                                    30
#define PTP_V2_CONTROLFIELD_OFFSET                                  32
#define PTP_V2_LOGMESSAGEPERIOD_OFFSET                              33


/* Offsets for PTP_Announce (=AN) messages */
#define PTP_V2_AN_ORIGINTIMESTAMP_OFFSET                            34
#define PTP_V2_AN_ORIGINTIMESTAMPSECONDS_OFFSET                     34
#define PTP_V2_AN_ORIGINTIMESTAMPNANOSECONDS_OFFSET                 40
#define PTP_V2_AN_ORIGINCURRENTUTCOFFSET_OFFSET                     44
#define PTP_V2_AN_PRIORITY_1_OFFSET                                 47
#define PTP_V2_AN_GRANDMASTERCLOCKCLASS_OFFSET                      48
#define PTP_V2_AN_GRANDMASTERCLOCKACCURACY_OFFSET                   49
#define PTP_V2_AN_GRANDMASTERCLOCKVARIANCE_OFFSET                   50
#define PTP_V2_AN_PRIORITY_2_OFFSET                                 52
#define PTP_V2_AN_GRANDMASTERCLOCKIDENTITY_OFFSET                   53
#define PTP_V2_AN_LOCALSTEPSREMOVED_OFFSET                          61
#define PTP_V2_AN_TIMESOURCE_OFFSET                                 63
#define PTP_V2_AN_TLV_OFFSET                                        64 /* TLV only used if message length is > 64 bytes */

/* Announce TLV field offsets */
#define PTP_V2_AN_TLV_TYPE_OFFSET                                    0
#define PTP_V2_AN_TLV_LENGTHFIELD_OFFSET                             2

/* PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION field offsets */
#define PTP_V2_AN_TLV_OE_ORGANIZATIONID_OFFSET                       4
#define PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET                  7
#define PTP_V2_AN_TLV_OE_DATAFIELD_OFFSET                           10

/* PTPv2 White Rabbit TLV (organization extension subtype) field offsets */
#define PTP_V2_AN_TLV_OE_WRTLV_MESSAGEID_OFFSET                     10
#define PTP_V2_AN_TLV_OE_WRTLV_FLAGS_OFFSET                         12

/* PTPv2 IEEE_C37_238 TLV (organization extension subtype) field offsets */
#define PTP_V2_AN_TLV_OE_IEEEC37238TLV_GMID_OFFSET                  10
#define PTP_V2_AN_TLV_OE_IEEEC37238TLV_GMINACCURACY_OFFSET          12
#define PTP_V2_AN_TLV_OE_IEEEC37238TLV_NWINACCURACY_OFFSET          16
#define PTP_V2_AN_TLV_OE_IEEEC37238TLV_RESERVED_OFFSET              20

/* PTPv2 IEEE_C37_238-2017 TLV additional field offsets */
#define PTP_V2_AN_TLV_OE_IEEEC372382017TLV_RESERVED_OFFSET          12
#define PTP_V2_AN_TLV_OE_IEEEC37238TLV_TOTALINACCURACY_OFFSET       16

/* PTP_V2_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR field offsets */
#define PTP_V2_AN_TLV_ATOI_KEYFIELD_OFFSET                           4
#define PTP_V2_AN_TLV_ATOI_CURRENTOFFSET_OFFSET                      5
#define PTP_V2_AN_TLV_ATOI_JUMPSECONDS_OFFSET                        9
#define PTP_V2_AN_TLV_ATOI_TIMEOFNEXTJUMP_OFFSET                    13
#define PTP_V2_AN_TLV_ATOI_DISPLAYNAME_OFFSET                       19

/* Undissected TLV field offset */
#define PTP_V2_AN_TLV_DATA_OFFSET                                    4

/* 802.1AS Path Sequence Offset */
#define PTP_AS_AN_TLV_PATH_TRACE_OFFSET                              4

/* Offsets for PTP_Sync AND PTP_DelayRequest (=SDR) messages */
#define PTP_V2_SDR_ORIGINTIMESTAMP_OFFSET                           34
#define PTP_V2_SDR_ORIGINTIMESTAMPSECONDS_OFFSET                    34
#define PTP_V2_SDR_ORIGINTIMESTAMPNANOSECONDS_OFFSET                40

/* Offsets for PTP_Follow_Up (=FU) messages */
#define PTP_V2_FU_PRECISEORIGINTIMESTAMP_OFFSET                     34
#define PTP_V2_FU_PRECISEORIGINTIMESTAMPSECONDS_OFFSET              34
#define PTP_V2_FU_PRECISEORIGINTIMESTAMPNANOSECONDS_OFFSET          40

/* 802.1AS Follow_Up information TLV */
#define PTP_AS_FU_TLV_INFORMATION_OFFSET                            44

/* 802.1AS Follow_Up TLV field offsets */
#define PTP_AS_FU_TLV_TYPE_OFFSET                                    0
#define PTP_AS_FU_TLV_LENGTHFIELD_OFFSET                             2
#define PTP_AS_FU_TLV_ORGANIZATIONID_OFFSET                          4
#define PTP_AS_FU_TLV_ORGANIZATIONSUBTYPE_OFFSET                     7
#define PTP_AS_FU_TLV_CUMULATIVESCALEDRATEOFFSET_OFFSET             10
#define PTP_AS_FU_TLV_GMTIMEBASEINDICATOR_OFFSET                    14
#define PTP_AS_FU_TLV_LASTGMPHASECHANGE_OFFSET                      16
#define PTP_AS_FU_TLV_SCALEDLASTGMFREQCHANGE_OFFSET                 28

/* Offsets for PTP_DelayResponse (=DR) messages */
#define PTP_V2_DR_RECEIVETIMESTAMP_OFFSET                           34
#define PTP_V2_DR_RECEIVETIMESTAMPSECONDS_OFFSET                    34
#define PTP_V2_DR_RECEIVETIMESTAMPNANOSECONDS_OFFSET                40
#define PTP_V2_DR_REQUESTINGPORTIDENTITY_OFFSET                     44
#define PTP_V2_DR_REQUESTINGSOURCEPORTID_OFFSET                     52

/* Offsets for PTP_PDelayRequest (=PDRQ) messages */
#define PTP_V2_PDRQ_ORIGINTIMESTAMP_OFFSET                          34
#define PTP_V2_PDRQ_ORIGINTIMESTAMPSECONDS_OFFSET                   34
#define PTP_V2_PDRQ_ORIGINTIMESTAMPNANOSECONDS_OFFSET               40
#define PTP_V2_PDRQ_RESERVED_OFFSET                                 44

/* Offsets for PTP_PDelayResponse (=PDRS) messages */
#define PTP_V2_PDRS_REQUESTRECEIPTTIMESTAMP_OFFSET                  34
#define PTP_V2_PDRS_REQUESTRECEIPTTIMESTAMPSECONDS_OFFSET           34
#define PTP_V2_PDRS_REQUESTRECEIPTTIMESTAMPNANOSECONDS_OFFSET       40
#define PTP_V2_PDRS_REQUESTINGPORTIDENTITY_OFFSET                   44 /* ++ */
#define PTP_V2_PDRS_REQUESTINGSOURCEPORTID_OFFSET                   52 /* ++ */


/* Offsets for PTP_PDelayResponseFollowUp (=PDFU) messages */
#define PTP_V2_PDFU_RESPONSEORIGINTIMESTAMP_OFFSET                  34
#define PTP_V2_PDFU_RESPONSEORIGINTIMESTAMPSECONDS_OFFSET           34
#define PTP_V2_PDFU_RESPONSEORIGINTIMESTAMPNANOSECONDS_OFFSET       40
#define PTP_V2_PDFU_REQUESTINGPORTIDENTITY_OFFSET                   44 /* ++ */
#define PTP_V2_PDFU_REQUESTINGSOURCEPORTID_OFFSET                   52


/* Offsets for PTP_Signalling (=SIG) messages */
#define PTP_V2_SIG_TARGETPORTIDENTITY_OFFSET                        34
#define PTP_V2_SIG_TARGETPORTID_OFFSET                              42
#define PTP_V2_SIG_TLV_START                                        44

/* Offset for PTP Signaling messages (relative to tlvOffset!) */
#define PTP_V2_SIG_TLV_TYPE_OFFSET                                  0
#define PTP_V2_SIG_TLV_LENGTH_OFFSET                                2
#define PTP_V2_SIG_TLV_VALUE_OFFSET                                 4
#define PTP_V2_SIG_TLV_MESSAGE_TYPE_OFFSET                          4
#define PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET              5
#define PTP_V2_SIG_TLV_DURATION_FIELD_OFFSET                        6
#define PTP_V2_SIG_TLV_RENEWAL_INVITED_OFFSET                       11

#define PTP_V2_SIG_TLV_TYPE_LEN                                     2
#define PTP_V2_SIG_TLV_LENGTH_LEN                                   2
#define PTP_V2_SIG_TLV_MESSAGE_TYPE_LEN                             1
#define PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN                 1
#define PTP_V2_SIG_TLV_DURATION_FIELD_LEN                           4
#define PTP_V2_SIG_TLV_RENEWAL_INVITED_LEN                          1

/* PTPv2.1 L1 SYNC flags field length */
#define PTP_V2_SIG_TLV_L1SYNC_FLAGS_BASIC_FORMAT                    2
#define PTP_V2_SIG_TLV_L1SYNC_FLAGS_EXT_FORMAT                      3

/* PTPv2.1 L1 SYNC field offsets */
#define PTP_V2_SIG_TLV_L1SYNC_FLAGS_OFFSET                          4
#define PTP_V2_SIG_TLV_L1SYNC_FLAGS1_OFFSET                         4
#define PTP_V2_SIG_TLV_L1SYNC_FLAGS2_OFFSET                         5
#define PTP_V2_SIG_TLV_L1SYNCEXT_FLAGS3_OFFSET                      6
#define PTP_V2_SIG_TLV_L1SYNCEXT_PHASE_OFFSET_TX_OFFSET             7
#define PTP_V2_SIG_TLV_L1SYNCEXT_PHASE_OFFSET_TX_TIMESTAMP_OFFSET   15
#define PTP_V2_SIG_TLV_L1SYNCEXT_FREQ_OFFSET_TX_OFFSET              25
#define PTP_V2_SIG_TLV_L1SYNCEXT_FREQ_OFFSET_TX_TIMESTAMP_OFFSET    33

/* PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION field offsets */
#define PTP_V2_SIG_TLV_ORGANIZATIONID_OFFSET                        4
#define PTP_V2_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET                   7
#define PTP_V2_SIG_TLV_DATAFIELD_OFFSET                             10

/* PTPv2 White Rabbit (WR) TLV (organization extension subtype) field offsets */
#define PTP_V2_SIG_TLV_WRTLV_MESSAGEID_OFFSET                       10

#define PTP_V2_SIG_TLV_WRTLV_CALSENDPATTERN_OFFSET                  12
#define PTP_V2_SIG_TLV_WRTLV_CALRETRY_OFFSET                        13
#define PTP_V2_SIG_TLV_WRTLV_CALPERIOD_OFFSET                       14

#define PTP_V2_SIG_TLV_WRTLV_DELTATX_OFFSET                         12
#define PTP_V2_SIG_TLV_WRTLV_DELTARX_OFFSET                         20

/* 802.1AS Signalling Message Interval Request TLV */
#define PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET                44

/* 802.1AS Signalling TLV field offsets */
#define PTP_AS_SIG_TLV_TYPE_OFFSET                                   0
#define PTP_AS_SIG_TLV_LENGTHFIELD_OFFSET                            2
#define PTP_AS_SIG_TLV_ORGANIZATIONID_OFFSET                         4
#define PTP_AS_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET                    7

#define PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_LINKDELAYINTERVAL_OFFSET   10
#define PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_TIMESYNCINTERVAL_OFFSET    11
#define PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_ANNOUNCEINTERVAL_OFFSET    12
#define PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_FLAGS_OFFSET               13

#define PTP_AS_SIG_TLV_GPTPCAPABLE_MESSAGEINTERVAL_OFFSET            10
#define PTP_AS_SIG_TLV_GPTPCAPABLE_FLAGS_OFFSET                      11

#define PTP_AS_SIG_TLV_TYPE_MESSAGEINTERVALREQUEST                   0x0003
#define PTP_AS_SIG_TLV_TYPE_GPTPCAPABLE                              0x8000

/*Defined in 10.6.4.4.5*/
#define PTP_AS_SIG_TLV_TYPE_GPTPCAPABLE_ORG_SUB_TYPE                  4
/*Defined in 10.6.4.5.5*/
#define PTP_AS_SIG_TLV_TYPE_GPTPCAPABLE_MESSSAGEINTERVAL_ORG_SUB_TYPE 5

/**********************************************************/
/* Message Interval Request flag-field-mask-definitions   */
/**********************************************************/
#define PTP_AS_FLAGS_COMP_NEIGHBOR_RATE_RATIO_BITMASK           0x02
#define PTP_AS_FLAGS_COMP_MEAN_LINK_DELAY_BITMASK               0x04
#define PTP_AS_FLAGS_ONE_STEP_RECEIVE_CAPABLE                   0x08

/* Offsets for PTP_V2_Management (=MM) messages */
#define PTP_V2_MM_TARGETPORTIDENTITY_OFFSET             34
#define PTP_V2_MM_TARGETPORTID_OFFSET                   42
#define PTP_V2_MM_STARTINGBOUNDARYHOPS_OFFSET           44
#define PTP_V2_MM_BOUNDARYHOPS_OFFSET                   45
#define PTP_V2_MM_ACTION_OFFSET                         46
#define PTP_V2_MM_RESERVED_OFFSET                       47

#define PTP_V2_MM_MANAGEMENTTLV_OFFSET                  48
/* Management TLV */
#define PTP_V2_MM_TLV_TYPE_OFFSET                       48
#define PTP_V2_MM_TLV_LENGTHFIELD_OFFSET                50
#define PTP_V2_MM_TLV_MANAGEMENTID_OFFSET               52
#define PTP_V2_MM_TLV_MANAGEMENTERRORID_OFFSET          52
#define PTP_V2_MM_TLV_DATAFIELD_OFFSET                  54

/* TLV Types */
#define PTP_V2_TLV_TYPE_RESERVED                                0x0000
#define PTP_V2_TLV_TYPE_MANAGEMENT                              0x0001
#define PTP_V2_TLV_TYPE_MANAGEMENT_ERROR_STATUS                 0x0002
#define PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION                  0x0003
#define PTP_V2_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION            0x0004
#define PTP_V2_TLV_TYPE_GRANT_UNICAST_TRANSMISSION              0x0005
#define PTP_V2_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION             0x0006
#define PTP_V2_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION 0x0007
#define PTP_V2_TLV_TYPE_PATH_TRACE                              0x0008
#define PTP_V2_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR         0x0009
#define PTP_V2_TLV_TYPE_AUTHENTICATION                          0x2000
#define PTP_V2_TLV_TYPE_AUTHENTICATION_CHALLENGE                0x2001
#define PTP_V2_TLV_TYPE_SECURITY_ASSOCIATION_UPDATE             0x2002
#define PTP_V2_TLV_TYPE_CUM_FREQ_SCALE_FACTOR_OFFSET            0x2003
#define PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION_PROPAGATE        0x4000
#define PTP_V2_TLV_TYPE_ENHANCED_ACCURACY_METRICS               0x4001
#define PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE 0x8000
#define PTP_V2_TLV_TYPE_L1_SYNC                                 0x8001
#define PTP_V2_TLV_TYPE_PORT_COMMUNICATION_AVAILABILITY         0x8002
#define PTP_V2_TLV_TYPE_PROTOCOL_ADDRESS                        0x8003
#define PTP_V2_TLV_TYPE_SLAVE_RX_SYNC_TIMING_DATA               0x8004
#define PTP_V2_TLV_TYPE_SLAVE_RX_SYNC_COMPUTED_DATA             0x8005
#define PTP_V2_TLV_TYPE_SLAVE_TX_EVENT_TIMESTAMPS               0x8006
#define PTP_V2_TLV_TYPE_CUMULATIVE_RATE_RATIO                   0x8007
#define PTP_V2_TLV_TYPE_PAD                                     0x8008
#define PTP_V2_TLV_TYPE_AUTHENTICATION2                         0x8009

/* Signalling TLV Object IDs */
#define PTP_AS_TLV_OID_TYPE_802                               0x0080C2

/* PTPv2 Management clockType Boolean[16] Bits mask */
#define CLOCKTYPE_ORDINARY_CLOCK                                0x8000
#define CLOCKTYPE_BOUNDARY_CLOCK                                0x4000
#define CLOCKTYPE_P2P_TC                                        0x2000
#define CLOCKTYPE_E2E_TC                                        0x1000
#define CLOCKTYPE_MANAGEMENT_NODE                               0x0800
#define CLOCKTYPE_RESERVED                                      0x07FF

/* PTPv2 Management IDs */
#define PTP_V2_MM_ID_NULL_MANAGEMENT                            0x0000
#define PTP_V2_MM_ID_CLOCK_DESCRIPTION                          0x0001
#define PTP_V2_MM_ID_USER_DESCRIPTION                           0x0002
#define PTP_V2_MM_ID_SAVE_IN_NON_VOLATILE_STORAGE               0x0003
#define PTP_V2_MM_ID_RESET_NON_VOLATILE_STORAGE                 0x0004
#define PTP_V2_MM_ID_INITIALIZE                                 0x0005
#define PTP_V2_MM_ID_FAULT_LOG                                  0x0006
#define PTP_V2_MM_ID_FAULT_LOG_RESET                            0x0007
#define PTP_V2_MM_ID_DEFAULT_DATA_SET                           0x2000
#define PTP_V2_MM_ID_CURRENT_DATA_SET                           0x2001
#define PTP_V2_MM_ID_PARENT_DATA_SET                            0x2002
#define PTP_V2_MM_ID_TIME_PROPERTIES_DATA_SET                   0x2003
#define PTP_V2_MM_ID_PORT_DATA_SET                              0x2004
#define PTP_V2_MM_ID_PRIORITY1                                  0x2005
#define PTP_V2_MM_ID_PRIORITY2                                  0x2006
#define PTP_V2_MM_ID_DOMAIN                                     0x2007
#define PTP_V2_MM_ID_SLAVE_ONLY                                 0x2008
#define PTP_V2_MM_ID_LOG_ANNOUNCE_INTERVAL                      0x2009
#define PTP_V2_MM_ID_ANNOUNCE_RECEIPT_TIMEOUT                   0x200A
#define PTP_V2_MM_ID_LOG_SYNC_INTERVAL                          0x200B
#define PTP_V2_MM_ID_VERSION_NUMBER                             0x200C
#define PTP_V2_MM_ID_ENABLE_PORT                                0x200D
#define PTP_V2_MM_ID_DISABLE_PORT                               0x200E
#define PTP_V2_MM_ID_TIME                                       0x200F
#define PTP_V2_MM_ID_CLOCK_ACCURACY                             0x2010
#define PTP_V2_MM_ID_UTC_PROPERTIES                             0x2011
#define PTP_V2_MM_ID_TRACEABILITY_PROPERTIES                    0x2012
#define PTP_V2_MM_ID_TIMESCALE_PROPERTIES                       0x2013
#define PTP_V2_MM_ID_UNICAST_NEGOTIATION_ENABLE                 0x2014
#define PTP_V2_MM_ID_PATH_TRACE_LIST                            0x2015
#define PTP_V2_MM_ID_PATH_TRACE_ENABLE                          0x2016
#define PTP_V2_MM_ID_GRANDMASTER_CLUSTER_TABLE                  0x2017
#define PTP_V2_MM_ID_UNICAST_MASTER_TABLE                       0x2018
#define PTP_V2_MM_ID_UNICAST_MASTER_MAX_TABLE_SIZE              0x2019
#define PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE                    0x201A
#define PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE_ENABLED            0x201B
#define PTP_V2_MM_ID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE           0x201C
#define PTP_V2_MM_ID_ALTERNATE_MASTER                           0x201D
#define PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_ENABLE               0x201E
#define PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_NAME                 0x201F
#define PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_MAX_KEY              0x2020
#define PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_PROPERTIES           0x2021
#define PTP_V2_MM_ID_EXTERNAL_PORT_CONFIGURATION_ENABLED        0x3001
#define PTP_V2_MM_ID_MASTER_ONLY                                0x3002
#define PTP_V2_MM_ID_HOLDOVER_UPGRADE_ENABLE                    0x3003
#define PTP_V2_MM_ID_EXT_PORT_CONFIG_PORT_DATA_SET              0x3004
#define PTP_V2_MM_ID_TC_DEFAULT_DATA_SET                        0x4000
#define PTP_V2_MM_ID_TC_PORT_DATA_SET                           0x4001
#define PTP_V2_MM_ID_PRIMARY_DOMAIN                             0x4002
#define PTP_V2_MM_ID_DELAY_MECHANISM                            0x6000
#define PTP_V2_MM_ID_LOG_MIN_PDELAY_REQ_INTERVAL                0x6001

/* Management DataField for DefaultDS */
#define PTP_V2_MM_RESERVED1                             PTP_V2_MM_TLV_DATAFIELD_OFFSET + 1
#define PTP_V2_MM_NUMBERPORTS                           PTP_V2_MM_TLV_DATAFIELD_OFFSET + 2
#define PTP_V2_MM_PRIORITY1                             PTP_V2_MM_TLV_DATAFIELD_OFFSET + 4
#define PTP_V2_MM_CLOCKQUALITY                          PTP_V2_MM_TLV_DATAFIELD_OFFSET + 5
#define PTP_V2_MM_PRIORITY2                             PTP_V2_MM_TLV_DATAFIELD_OFFSET + 9
#define PTP_V2_MM_CLOCKIDENTITY                         PTP_V2_MM_TLV_DATAFIELD_OFFSET + 10
#define PTP_V2_MM_DOMAINNUMBER                          PTP_V2_MM_TLV_DATAFIELD_OFFSET + 18
#define PTP_V2_MM_RESERVED2                             PTP_V2_MM_TLV_DATAFIELD_OFFSET + 19

/* Bitmasks for PTP_V2_SIG_TLV_L1SYNC_FLAGS1_OFFSET */
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_TCR_BITMASK     0x1 << 8
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_RCR_BITMASK     0x2 << 8
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_CR_BITMASK      0x4 << 8
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_OPE_BITMASK     0x8 << 8
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_RESERVED_BITMASK 0xF0 << 8

/* Bitmasks for PTP_V2_SIG_TLV_L1SYNC_FLAGS2_OFFSET */
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_ITC_BITMASK     0x1
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_IRC_BITMASK     0x2
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_IC_BITMASK      0x4
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_RESERVED_BITMASK 0xF8

/* Bitmasks for PTP_V2_SIG_TLV_L1SYNCEXT_FLAGS3_OFFSET */
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_TCT_BITMASK     0x1
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_POV_BITMASK     0x2
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_FOV_BITMASK     0x4
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_RESERVED_BITMASK 0xF8

/* Bitmasks for reserved values for standard and extended versions of L1_SYNC frames */
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_RESERVED_ALL_BITMASK \
        (PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_RESERVED_BITMASK \
        | PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_RESERVED_BITMASK)
#define PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_RESERVED_ALL_BITMASK \
        (PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_RESERVED_ALL_BITMASK << 8 \
        | PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_RESERVED_BITMASK)


/* Subtypes for the OUI_IEEE_C37_238 organization ID */
#define PTP_V2_OE_ORG_IEEE_C37_238_SUBTYPE_C37238TLV    1        /* Defined in IEEE Std C37.238-2011 */
#define PTP_V2_OE_ORG_IEEE_C37_238_SUBTYPE_C372382017TLV    2    /* Defined in IEEE Std C37.238-2017 */

/* Subtypes for the PTP_V2_OE_ORG_ID_SMPTE organization ID */
#define PTP_V2_OE_ORG_SMPTE_SUBTYPE_VERSION_TLV         1

/* Subtypes for the OUI_CERN organization ID */
#define PTP_V2_OE_ORG_CERN_SUBTYPE_WR_TLV               0xdead01

/* Subtypes for ITU-T organization ID */
#define PTP_V2_INTERFACE_RATE_TLV                       0x000002

/* MESSAGE ID for the PTP_V2_OE_ORG_CERN_SUBTYPE_WR_TLV */
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_NULL_WR_TLV      0x0000
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_SLAVE_PRESENT    0x1000
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_LOCK             0x1001
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_LOCKED           0x1002
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_CALIBRATE        0x1003
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_CALIBRATED       0x1004
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_WR_MODE_ON       0x1005
#define PTP_V2_OE_ORG_CERN_WRMESSAGEID_ANN_SUFIX        0x2000

/* Bitmasks for PTP_V2_AN_TLV_OE_WRTLV_FLAGS_OFFSET */
#define PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_BITMASK     0x3
#define PTP_V2_TLV_OE_CERN_WRFLAGS_CALIBRATED_BITMASK   0x4
#define PTP_V2_TLV_OE_CERN_WRFLAGS_WRMODEON_BITMASK     0x8

/* Values for PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_BITMASK */
#define PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_NON_WR      0
#define PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_WR_M_ONLY   1
#define PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_WR_S_ONLY   2
#define PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_WR_M_AND_S  3

#define PTP_V2_MAJORSDOID_ASPACKET_BITMASK                     0x10


/**********************************************************/
/* flag-field-mask-definitions                            */
/**********************************************************/
#define PTP_V2_FLAGS_LI61_BITMASK                                   0x0001
#define PTP_V2_FLAGS_LI59_BITMASK                                   0x0002
#define PTP_V2_FLAGS_UTC_OFFSET_VALID_BITMASK                       0x0004
#define PTP_V2_FLAGS_PTP_TIMESCALE_BITMASK                          0x0008
#define PTP_V2_FLAGS_TIME_TRACEABLE_BITMASK                         0x0010
#define PTP_V2_FLAGS_FREQUENCY_TRACEABLE_BITMASK                    0x0020
#define PTP_V2_FLAGS_SYNCHRONIZATION_UNCERTAIN_BITMASK              0x0040
#define PTP_V2_FLAGS_ALTERNATE_BITMASK                              0x0100
#define PTP_V2_FLAGS_TWO_STEP_BITMASK                               0x0200
#define PTP_V2_FLAGS_UNICAST_BITMASK                                0x0400
#define PTP_V2_FLAGS_SPECIFIC1_BITMASK                              0x2000
#define PTP_V2_FLAGS_SPECIFIC2_BITMASK                              0x4000
#define PTP_V2_FLAGS_SECURITY_BITMASK                               0x8000

#define PTP_V2_FLAGS_OE_SMPTE_TIME_ADDRESS_FIELD_DROP                0x01
#define PTP_V2_FLAGS_OE_SMPTE_TIME_ADDRESS_FIELD_COLOR               0x02

#define PTP_V2_FLAGS_OE_SMPTE_DAYLIGHT_SAVING_CURRENT               0x01
#define PTP_V2_FLAGS_OE_SMPTE_DAYLIGHT_SAVING_NEXT                  0x02
#define PTP_V2_FLAGS_OE_SMPTE_DAYLIGHT_SAVING_PREVIOUS              0x04

#define PTP_V2_FLAGS_OE_SMPTE_LEAP_SECOND_JUMP_CHANGE               0x01

/**********************************************************/
/* PTP v2 message ids   (ptp messageid field)             */
/**********************************************************/
#define PTP_V2_SYNC_MESSAGE                     0x00
#define PTP_V2_DELAY_REQ_MESSAGE                0x01
#define PTP_V2_PEER_DELAY_REQ_MESSAGE           0x02
#define PTP_V2_PEER_DELAY_RESP_MESSAGE          0x03
#define PTP_V2_FOLLOWUP_MESSAGE                 0x08
#define PTP_V2_DELAY_RESP_MESSAGE               0x09
#define PTP_V2_PEER_DELAY_FOLLOWUP_MESSAGE      0x0A
#define PTP_V2_ANNOUNCE_MESSAGE                 0x0B
#define PTP_V2_SIGNALLING_MESSAGE               0x0C
#define PTP_V2_MANAGEMENT_MESSAGE               0x0D



static const value_string ptp_v2_managementID_vals[] = {
    {PTP_V2_MM_ID_NULL_MANAGEMENT                   ,"NULL_MANAGEMENT"},
    {PTP_V2_MM_ID_CLOCK_DESCRIPTION                 ,"CLOCK_DESCRIPTION"},
    {PTP_V2_MM_ID_USER_DESCRIPTION                  ,"USER_DESCRIPTION"},
    {PTP_V2_MM_ID_SAVE_IN_NON_VOLATILE_STORAGE      ,"SAVE_IN_NON_VOLATILE_STORAGE"},
    {PTP_V2_MM_ID_RESET_NON_VOLATILE_STORAGE        ,"RESET_NON_VOLATILE_STORAGE"},
    {PTP_V2_MM_ID_INITIALIZE                        ,"INITIALIZE"},
    {PTP_V2_MM_ID_FAULT_LOG                         ,"FAULT_LOG"},
    {PTP_V2_MM_ID_FAULT_LOG_RESET                   ,"FAULT_LOG_RESET"},
    {PTP_V2_MM_ID_DEFAULT_DATA_SET                  ,"DEFAULT_DATA_SET"},
    {PTP_V2_MM_ID_CURRENT_DATA_SET                  ,"CURRENT_DATA_SET"},
    {PTP_V2_MM_ID_PARENT_DATA_SET                   ,"PARENT_DATA_SET"},
    {PTP_V2_MM_ID_TIME_PROPERTIES_DATA_SET          ,"TIME_PROPERTIES_DATA_SET"},
    {PTP_V2_MM_ID_PORT_DATA_SET                     ,"PORT_DATA_SET"},
    {PTP_V2_MM_ID_PRIORITY1                         ,"PRIORITY1"},
    {PTP_V2_MM_ID_PRIORITY2                         ,"PRIORITY2"},
    {PTP_V2_MM_ID_DOMAIN                            ,"DOMAIN"},
    {PTP_V2_MM_ID_SLAVE_ONLY                        ,"SLAVE_ONLY"},
    {PTP_V2_MM_ID_LOG_ANNOUNCE_INTERVAL             ,"LOG_ANNOUNCE_INTERVAL"},
    {PTP_V2_MM_ID_ANNOUNCE_RECEIPT_TIMEOUT          ,"ANNOUNCE_RECEIPT_TIMEOUT"},
    {PTP_V2_MM_ID_LOG_SYNC_INTERVAL                 ,"LOG_SYNC_INTERVAL"},
    {PTP_V2_MM_ID_VERSION_NUMBER                    ,"VERSION_NUMBER"},
    {PTP_V2_MM_ID_ENABLE_PORT                       ,"ENABLE_PORT"},
    {PTP_V2_MM_ID_DISABLE_PORT                      ,"DISABLE_PORT"},
    {PTP_V2_MM_ID_TIME                              ,"TIME"},
    {PTP_V2_MM_ID_CLOCK_ACCURACY                    ,"CLOCK_ACCURACY"},
    {PTP_V2_MM_ID_UTC_PROPERTIES                    ,"UTC_PROPERTIES"},
    {PTP_V2_MM_ID_TRACEABILITY_PROPERTIES           ,"TRACEABILITY_PROPERTIES"},
    {PTP_V2_MM_ID_TIMESCALE_PROPERTIES              ,"TIMESCALE_PROPERTIES"},
    {PTP_V2_MM_ID_UNICAST_NEGOTIATION_ENABLE        ,"UNICAST_NEGOTIATION_ENABLE"},
    {PTP_V2_MM_ID_PATH_TRACE_LIST                   ,"PATH_TRACE_LIST"},
    {PTP_V2_MM_ID_PATH_TRACE_ENABLE                 ,"PATH_TRACE_ENABLE"},
    {PTP_V2_MM_ID_GRANDMASTER_CLUSTER_TABLE         ,"GRANDMASTER_CLUSTER_TABLE"},
    {PTP_V2_MM_ID_UNICAST_MASTER_TABLE              ,"UNICAST_MASTER_TABLE"},
    {PTP_V2_MM_ID_UNICAST_MASTER_MAX_TABLE_SIZE     ,"UNICAST_MASTER_MAX_TABLE_SIZE"},
    {PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE           ,"ACCEPTABLE_MASTER_TABLE"},
    {PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE_ENABLED   ,"ACCEPTABLE_MASTER_TABLE_ENABLED"},
    {PTP_V2_MM_ID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE  ,"ACCEPTABLE_MASTER_MAX_TABLE_SIZE"},
    {PTP_V2_MM_ID_ALTERNATE_MASTER                  ,"ALTERNATE_MASTER"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_ENABLE      ,"ALTERNATE_TIME_OFFSET_ENABLE"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_NAME        ,"ALTERNATE_TIME_OFFSET_NAME"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_MAX_KEY     ,"ALTERNATE_TIME_OFFSET_MAX_KEY"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_PROPERTIES  ,"ALTERNATE_TIME_OFFSET_PROPERTIES"},
    {PTP_V2_MM_ID_EXTERNAL_PORT_CONFIGURATION_ENABLED,"EXTERNAL_PORT_CONFIGURATION_ENABLED"},
    {PTP_V2_MM_ID_MASTER_ONLY                       ,"MASTER_ONLY"},
    {PTP_V2_MM_ID_HOLDOVER_UPGRADE_ENABLE           ,"HOLDOVER_UPGRADE_ENABLE"},
    {PTP_V2_MM_ID_EXT_PORT_CONFIG_PORT_DATA_SET     ,"EXT_PORT_CONFIG_PORT_DATA_SET"},
    {PTP_V2_MM_ID_TC_DEFAULT_DATA_SET               ,"TC_DEFAULT_DATA_SET"},
    {PTP_V2_MM_ID_TC_PORT_DATA_SET                  ,"TC_PORT_DATA_SET"},
    {PTP_V2_MM_ID_PRIMARY_DOMAIN                    ,"PRIMARY_DOMAIN"},
    {PTP_V2_MM_ID_DELAY_MECHANISM                   ,"DELAY_MECHANISM"},
    {PTP_V2_MM_ID_LOG_MIN_PDELAY_REQ_INTERVAL       ,"LOG_MIN_PDELAY_REQ_INTERVAL"},
    {0                                              ,NULL}
};
static value_string_ext ptp_v2_managementID_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_managementID_vals);

/* same again but better readable text for info column */
static const value_string ptp_v2_managementID_infocolumn_vals[] = {
    {PTP_V2_MM_ID_NULL_MANAGEMENT                   ,"Null management"},
    {PTP_V2_MM_ID_CLOCK_DESCRIPTION                 ,"Clock description"},
    {PTP_V2_MM_ID_USER_DESCRIPTION                  ,"User description"},
    {PTP_V2_MM_ID_SAVE_IN_NON_VOLATILE_STORAGE      ,"Save in non volatile storage"},
    {PTP_V2_MM_ID_RESET_NON_VOLATILE_STORAGE        ,"Reset non volatile storage"},
    {PTP_V2_MM_ID_INITIALIZE                        ,"Initialize"},
    {PTP_V2_MM_ID_FAULT_LOG                         ,"Fault log"},
    {PTP_V2_MM_ID_FAULT_LOG_RESET                   ,"Fault log reset"},
    {PTP_V2_MM_ID_DEFAULT_DATA_SET                  ,"Default dataset"},
    {PTP_V2_MM_ID_CURRENT_DATA_SET                  ,"Current dataset"},
    {PTP_V2_MM_ID_PARENT_DATA_SET                   ,"Parent dataset"},
    {PTP_V2_MM_ID_TIME_PROPERTIES_DATA_SET          ,"Time properties dataset"},
    {PTP_V2_MM_ID_PORT_DATA_SET                     ,"Port dataset"},
    {PTP_V2_MM_ID_PRIORITY1                         ,"Priority 1"},
    {PTP_V2_MM_ID_PRIORITY2                         ,"Priority 2"},
    {PTP_V2_MM_ID_DOMAIN                            ,"Domain"},
    {PTP_V2_MM_ID_SLAVE_ONLY                        ,"Slave only"},
    {PTP_V2_MM_ID_LOG_ANNOUNCE_INTERVAL             ,"Log announce interval"},
    {PTP_V2_MM_ID_ANNOUNCE_RECEIPT_TIMEOUT          ,"Announce receipt timeout"},
    {PTP_V2_MM_ID_LOG_SYNC_INTERVAL                 ,"Log sync interval"},
    {PTP_V2_MM_ID_VERSION_NUMBER                    ,"Version number"},
    {PTP_V2_MM_ID_ENABLE_PORT                       ,"Enable port"},
    {PTP_V2_MM_ID_DISABLE_PORT                      ,"Disable port"},
    {PTP_V2_MM_ID_TIME                              ,"Time"},
    {PTP_V2_MM_ID_CLOCK_ACCURACY                    ,"Clock accuracy"},
    {PTP_V2_MM_ID_UTC_PROPERTIES                    ,"UTC properties"},
    {PTP_V2_MM_ID_TRACEABILITY_PROPERTIES           ,"Traceability properties"},
    {PTP_V2_MM_ID_TIMESCALE_PROPERTIES              ,"Timescale properties"},
    {PTP_V2_MM_ID_UNICAST_NEGOTIATION_ENABLE        ,"Unicast negotiation enable"},
    {PTP_V2_MM_ID_PATH_TRACE_LIST                   ,"Path trace list"},
    {PTP_V2_MM_ID_PATH_TRACE_ENABLE                 ,"Path trace enable"},
    {PTP_V2_MM_ID_GRANDMASTER_CLUSTER_TABLE         ,"Grandmaster cluster table"},
    {PTP_V2_MM_ID_UNICAST_MASTER_TABLE              ,"Unicast master table"},
    {PTP_V2_MM_ID_UNICAST_MASTER_MAX_TABLE_SIZE     ,"Unicast master max table size"},
    {PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE           ,"Acceptable master table"},
    {PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE_ENABLED   ,"Acceptable master table enabled"},
    {PTP_V2_MM_ID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE  ,"Acceptable master max table size"},
    {PTP_V2_MM_ID_ALTERNATE_MASTER                  ,"Alternate master"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_ENABLE      ,"Alternate time offset enable"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_NAME        ,"Alternate time offset name"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_MAX_KEY     ,"Alternate time offset max key"},
    {PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_PROPERTIES  ,"Alternate time offset properties"},
    {PTP_V2_MM_ID_EXTERNAL_PORT_CONFIGURATION_ENABLED,"External port configuration enabled"},
    {PTP_V2_MM_ID_MASTER_ONLY                       ,"Master only"},
    {PTP_V2_MM_ID_HOLDOVER_UPGRADE_ENABLE           ,"Holdover upgrade enable"},
    {PTP_V2_MM_ID_EXT_PORT_CONFIG_PORT_DATA_SET     ,"External port config port data set"},
    {PTP_V2_MM_ID_TC_DEFAULT_DATA_SET               ,"Transparent clock default dataset"},
    {PTP_V2_MM_ID_TC_PORT_DATA_SET                  ,"Transparent clock port dataset"},
    {PTP_V2_MM_ID_PRIMARY_DOMAIN                    ,"Primary domain"},
    {PTP_V2_MM_ID_DELAY_MECHANISM                   ,"Delay mechanism"},
    {PTP_V2_MM_ID_LOG_MIN_PDELAY_REQ_INTERVAL       ,"Log min pdelay req. interval"},
    {0                                              , NULL}
};
static value_string_ext ptp_v2_managementID_infocolumn_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_managementID_infocolumn_vals);

static const value_string ptp_v2_TLV_type_vals[] = {
    {PTP_V2_TLV_TYPE_RESERVED                       ,"Reserved"},
    {PTP_V2_TLV_TYPE_MANAGEMENT                     ,"Management"},
    {PTP_V2_TLV_TYPE_MANAGEMENT_ERROR_STATUS        ,"Management error status"},
    {PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION         ,"Organization extension"},
    {PTP_V2_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION   ,"Request unicast transmission"},
    {PTP_V2_TLV_TYPE_GRANT_UNICAST_TRANSMISSION     ,"Grant unicast transmission"},
    {PTP_V2_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION    ,"Cancel unicast transmission"},
    {PTP_V2_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION    ,"Acknowledge cancel unicast transmission"},
    {PTP_V2_TLV_TYPE_PATH_TRACE                     ,"Path trace"},
    {PTP_V2_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR,"Alternate time offset indicator"},
    {PTP_V2_TLV_TYPE_AUTHENTICATION                 ,"Authentication"},
    {PTP_V2_TLV_TYPE_AUTHENTICATION_CHALLENGE       ,"Authentication challenge"},
    {PTP_V2_TLV_TYPE_SECURITY_ASSOCIATION_UPDATE    ,"Security association update"},
    {PTP_V2_TLV_TYPE_CUM_FREQ_SCALE_FACTOR_OFFSET   ,"Cum. freq. scale factor offset"},
    {PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION_PROPAGATE,"Organization extension propagate"},
    {PTP_V2_TLV_TYPE_ENHANCED_ACCURACY_METRICS      ,"Enhanced accuracy metrics"},
    {PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION_DO_NOT_PROPAGATE, "Organization extension do not propagate"},
    {PTP_V2_TLV_TYPE_L1_SYNC                        ,"L1 sync"},
    {PTP_V2_TLV_TYPE_PORT_COMMUNICATION_AVAILABILITY,"Port communication availability"},
    {PTP_V2_TLV_TYPE_PROTOCOL_ADDRESS               ,"Protocol address"},
    {PTP_V2_TLV_TYPE_SLAVE_RX_SYNC_TIMING_DATA      ,"Slave rx sync timing data"},
    {PTP_V2_TLV_TYPE_SLAVE_RX_SYNC_COMPUTED_DATA    ,"Slave rx sync computed data"},
    {PTP_V2_TLV_TYPE_SLAVE_TX_EVENT_TIMESTAMPS      ,"Slave tx event timestamps"},
    {PTP_V2_TLV_TYPE_CUMULATIVE_RATE_RATIO          ,"Cumulative rate ratio"},
    {PTP_V2_TLV_TYPE_PAD                            ,"Pad"},
    {PTP_V2_TLV_TYPE_AUTHENTICATION2                ,"Authentication"},
    {0                                              , NULL}
};
static value_string_ext ptp_v2_TLV_type_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_TLV_type_vals);

static const value_string ptp_as_TLV_oid_vals[] = {
    {PTP_AS_TLV_OID_TYPE_802                        ,"IEEE 802"},
    {0                                              , NULL}
};

static const value_string ptp_v2_networkProtocol_vals[] = {
    {0x0000,  "Reserved"},
    {0x0001,  "UDP/IPv4"},
    {0x0002,  "UDP/IPv6"},
    {0x0003,  "IEEE 802.3"},
    {0x0004,  "DeviceNet"},
    {0x0005,  "ControlNet"},
    {0x0006,  "PROFINET"},
    {0x0007,  "Reserved"},
    {0xFFFE,  "Unknown Protocol"},
    {0xFFFF,  "Reserved"},
    {0,              NULL          }
};
static value_string_ext ptp_v2_networkProtocol_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_networkProtocol_vals);


static const value_string ptp_v2_messagetype_vals[] = {
    {PTP_V2_SYNC_MESSAGE,               "Sync Message"},
    {PTP_V2_DELAY_REQ_MESSAGE,          "Delay_Req Message"},
    {PTP_V2_PEER_DELAY_REQ_MESSAGE,     "Peer_Delay_Req Message"},
    {PTP_V2_PEER_DELAY_RESP_MESSAGE,    "Peer_Delay_Resp Message"},
    {PTP_V2_FOLLOWUP_MESSAGE,           "Follow_Up Message"},
    {PTP_V2_DELAY_RESP_MESSAGE,         "Delay_Resp Message"},
    {PTP_V2_PEER_DELAY_FOLLOWUP_MESSAGE,"Peer_Delay_Resp_Follow_Up Message"},
    {PTP_V2_ANNOUNCE_MESSAGE,           "Announce Message"},
    {PTP_V2_SIGNALLING_MESSAGE,         "Signalling Message"},
    {PTP_V2_MANAGEMENT_MESSAGE,         "Management Message"},
    {0,                                  NULL }
};
static value_string_ext ptp_v2_messagetype_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_messagetype_vals);

static const value_string ptp_v2_clockAccuracy_vals[] = {
    {0x17,  "The time is accurate to within 1 ps"},
    {0x18,  "The time is accurate to within 2,5 ps"},
    {0x19,  "The time is accurate to within 10 ps"},
    {0x1A,  "The time is accurate to within 25 ps"},
    {0x1B,  "The time is accurate to within 100 ps"},
    {0x1C,  "The time is accurate to within 250 ps"},
    {0x1D,  "The time is accurate to within 1 ns"},
    {0x1E,  "The time is accurate to within 2,5 ns"},
    {0x1F,  "The time is accurate to within 10 ns"},
    {0x20,  "The time is accurate to within 25 ns"},
    {0x21,  "The time is accurate to within 100 ns"},
    {0x22,  "The time is accurate to within 250 ns"},
    {0x23,  "The time is accurate to within 1 us"},
    {0x24,  "The time is accurate to within 2,5 us"},
    {0x25,  "The time is accurate to within 10 us"},
    {0x26,  "The time is accurate to within 25 us"},
    {0x27,  "The time is accurate to within 100 us"},
    {0x28,  "The time is accurate to within 250 us"},
    {0x29,  "The time is accurate to within 1 ms"},
    {0x2A,  "The time is accurate to within 2,5 ms"},
    {0x2B,  "The time is accurate to within 10 ms"},
    {0x2C,  "The time is accurate to within 25 ms"},
    {0x2D,  "The time is accurate to within 100 ms"},
    {0x2E,  "The time is accurate to within 250 ms"},
    {0x2F,  "The time is accurate to within 1 s"},
    {0x30,  "The time is accurate to within 10 s"},
    {0x31,  "The time is accurate to >10 s"},
    {0x32,  "reserved"},
    {0x80,  "For use by alternate PTP profiles"},
    {0xFE,  "Accuracy Unknown"},
    {0xFF,  "reserved"},
    {0,              NULL          }
};
/* Exposed in packet-ptp.h */
value_string_ext ptp_v2_clockAccuracy_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_clockAccuracy_vals);

static const value_string ptp_v2_timeSource_vals[] = {
    {0x10,  "ATOMIC_CLOCK"},
    {0x20,  "GPS"},
    {0x30,  "TERRESTRIAL_RADIO"},
    {0x39,  "SERIAL_TIME_CODE"},
    {0x40,  "PTP"},
    {0x50,  "NTP"},
    {0x60,  "HAND_SET"},
    {0x90,  "OTHER"},
    {0xA0,  "INTERNAL_OSCILLATOR"},
    {0xFF,  "reserved"},
    {0,              NULL          }
};
/* Exposed in packet-ptp.h */
value_string_ext ptp_v2_timeSource_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_timeSource_vals);

static const value_string ptp_v2_mm_action_vals[] = {
    {0x0,  "GET"},
    {0x1,  "SET"},
    {0x2,  "RESPONSE"},
    {0x3,  "COMMAND"},
    {0x4,  "ACKNOWLEDGE"},
    {0,              NULL          }
};

static const value_string ptp_v2_severityCode_vals[] = {
    {0x00,  "Emergency: system is unusable"},
    {0x01,  "Alert: immediate action needed"},
    {0x02,  "Critical: critical conditions"},
    {0x03,  "Error: error conditions"},
    {0x04,  "Warning: warning conditions"},
    {0x05,  "Notice: normal but significant condition"},
    {0x06,  "Informational: informational messages"},
    {0x07,  "Debug: debug-level messages"},
    {0x08,  "Reserved"},
    {0xFF,  "Reserved"},
    {0,      NULL}
};
static value_string_ext ptp_v2_severityCode_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_severityCode_vals);

static const value_string ptp_v2_portState_vals[] = {
    {0x01,  "INITIALIZING"},
    {0x02,  "FAULTY"},
    {0x03,  "DISABLED"},
    {0x04,  "LISTENING"},
    {0x05,  "PRE_MASTER"},
    {0x06,  "MASTER"},
    {0x07,  "PASSIVE"},
    {0x08,  "UNCALIBRATED"},
    {0x09,  "SLAVE"},
    {0,     NULL}
};
/* Exposed in packet-ptp.h */
value_string_ext ptp_v2_portState_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_portState_vals);

/* Exposed in packet-ptp.h */
const value_string ptp_v2_delayMechanism_vals[] = {
    {0x01,  "E2E"},
    {0x02,  "P2P"},
    {0x03,  "COMMON_P2P"},
    {0x04,  "SPECIAL"},
    {0xFE,  "NO_MECHANISM"},
    {0,     NULL}
};

static const value_string ptp_v2_managementErrorId_vals[] = {
    {0x0000,  "Reserved"},
    {0x0001,  "RESPONSE_TOO_BIG"},
    {0x0002,  "NO_SUCH_ID"},
    {0x0003,  "WRONG_LENGTH"},
    {0x0004,  "WRONG_VALUE"},
    {0x0005,  "NOT_SETABLE"},
    {0x0006,  "NOT_SUPPORTED"},
    {0x0007,  "Reserved"},
    {0xFFFE,  "GENERAL_ERROR"},
    {0xFFFF,  "Reserved"},
    {0,     NULL}
};
static value_string_ext ptp_v2_managementErrorId_vals_ext =
    VALUE_STRING_EXT_INIT(ptp_v2_managementErrorId_vals);

static const value_string ptp_v2_org_iee_c37_238_subtype_vals[] = {
    {PTP_V2_OE_ORG_IEEE_C37_238_SUBTYPE_C37238TLV,  "IEEE_C37_238 TLV"},
    {0,                                             NULL}
};

static const value_string ptp_v2_org_iee_c37_238_2017_subtype_vals[] = {
    {PTP_V2_OE_ORG_IEEE_C37_238_SUBTYPE_C372382017TLV,  "IEEE_C37_238_2017 TLV"},
    {0,                                             NULL}
};

static const value_string ptp_v2_org_smpte_subtype_vals[] = {
    {PTP_V2_OE_ORG_SMPTE_SUBTYPE_VERSION_TLV,  "Version"},
    {0,                                             NULL}
};

static const value_string ptp_v2_org_cern_subtype_vals[] = {
    {PTP_V2_OE_ORG_CERN_SUBTYPE_WR_TLV,  "White Rabbit"},
    {0,                                  NULL}
};

static const value_string ptp_v2_org_itut_subtype_vals[] = {
    {PTP_V2_INTERFACE_RATE_TLV,  "Interface Rate TLV"},
    {0,                          NULL}
};

static const value_string ptp_v2_org_cern_wrMessageID_vals[] = {
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_NULL_WR_TLV,  "NULL_WR_TLV"},
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_SLAVE_PRESENT,"SLAVE_PRESENT"},
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_LOCK,         "LOCK"},
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_LOCKED,       "LOCKED"},
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_CALIBRATE,    "CALIBRATE"},
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_CALIBRATED,   "CALIBRATED"},
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_WR_MODE_ON,   "WR_MODE_ON"},
    {PTP_V2_OE_ORG_CERN_WRMESSAGEID_ANN_SUFIX,    "ANN_SUFIX"},
    {0,                                           NULL}
};

static const value_string ptp_v2_tlv_oe_cern_wrFlags_wrConfig_vals[] = {
    {PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_NON_WR,     "NON WR"},
    {PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_WR_M_ONLY,  "WR_M_ONLY"},
    {PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_WR_S_ONLY,  "WR_S_ONLY"},
    {PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_WR_M_AND_S, "WR_M_AND_S"},
    {0,                                              NULL}
};

static const value_string ptp_v2_org_smpte_subtype_masterlockingstatus_vals[] = {
    {0,  "Not in use"},
    {1,  "Free Run"},
    {2,  "Cold Locking"},
    {3,  "Warm Locking"},
    {4,  "Locked"},
    {0,  NULL}
};

/**********************************************************/
/* MajorSdoId values for the PTPv2          */
/**********************************************************/
// 802.1AS 10.6.2.2.1 majorSdoId
static const value_string ptpv2_majorsdoid_vals[] = {
    {0x1, "gPTP Domain"},
    {0x2, "CMLDS"},
    {0,   NULL}
};

/* END PTPv2 MajorSdoId values */

/**********************************************************/
/* Initialize the protocol and registered fields          */
/**********************************************************/

static int hf_ptp_v2_majorsdoid;
static int hf_ptp_v2_messagetype;
static int hf_ptp_v2_minorversionptp;
static int hf_ptp_v2_versionptp;
static int hf_ptp_v2_messagelength;
static int hf_ptp_v2_minorsdoid;
static int hf_ptp_v2_domainnumber;
static int hf_ptp_v2_flags;
static int hf_ptp_v2_flags_alternatemaster;
static int hf_ptp_v2_flags_twostep;
static int hf_ptp_v2_flags_unicast;
static int hf_ptp_v2_flags_specific1;
static int hf_ptp_v2_flags_specific2;
static int hf_ptp_v2_flags_security;
static int hf_ptp_v2_flags_li61;
static int hf_ptp_v2_flags_li59;
static int hf_ptp_v2_flags_utcoffsetvalid;
static int hf_ptp_v2_flags_ptptimescale;
static int hf_ptp_v2_flags_timetraceable;
static int hf_ptp_v2_flags_frequencytraceable;
static int hf_ptp_v2_correction;
static int hf_ptp_v2_correctionsubns;
static int hf_ptp_v2_messagetypespecific;
static int hf_ptp_v2_clockidentity;
static int hf_ptp_v2_clockidentity_manuf;
static int hf_ptp_v2_sourceportid;
static int hf_ptp_v2_sequenceid;
static int hf_ptp_v2_controlfield;
static int hf_ptp_v2_controlfield_default;
static int hf_ptp_v2_logmessageperiod;
static int hf_ptp_v2_flags_synchronizationUncertain;


/* Fields for PTP_Announce (=an) messages */
/* static int hf_ptp_v2_an_origintimestamp; */   /* Field for seconds & nanoseconds */
static int hf_ptp_v2_an_origintimestamp_seconds;
static int hf_ptp_v2_an_origintimestamp_nanoseconds;
static int hf_ptp_v2_an_origincurrentutcoffset;
static int hf_ptp_v2_an_timesource;
static int hf_ptp_v2_an_localstepsremoved;
static int hf_ptp_v2_an_grandmasterclockidentity;
static int hf_ptp_v2_an_grandmasterclockclass;
static int hf_ptp_v2_an_grandmasterclockaccuracy;
static int hf_ptp_v2_an_grandmasterclockvariance;
static int hf_ptp_v2_an_priority1;
static int hf_ptp_v2_an_priority2;

/* Fields for PTP_Announce TLVs */
static int hf_ptp_v2_an_tlv_tlvtype;
static int hf_ptp_v2_an_tlv_lengthfield;
/* Fields for the ORGANIZATION_EXTENSION TLV */
static int hf_ptp_v2_oe_tlv_organizationid;
static int hf_ptp_v2_oe_tlv_organizationsubtype;
static int hf_ptp_v2_oe_tlv_2017_organizationsubtype;
static int hf_ptp_v2_oe_tlv_datafield;

/* Fields for CERN White Rabbit TLV (OE TLV subtype) */
static int hf_ptp_v2_an_tlv_oe_cern_subtype;
static int hf_ptp_v2_an_tlv_oe_cern_wrMessageID;
static int hf_ptp_v2_an_tlv_oe_cern_wrFlags;
static int hf_ptp_v2_an_tlv_oe_cern_wrFlags_wrConfig;
static int hf_ptp_v2_an_tlv_oe_cern_wrFlags_calibrated;
static int hf_ptp_v2_an_tlv_oe_cern_wrFlags_wrModeOn;

/* Fields for IEEE_C37_238 TLV (OE TLV subtype) */
static int hf_ptp_v2_oe_tlv_subtype_c37238tlv_grandmasterid;
static int hf_ptp_v2_oe_tlv_subtype_c37238tlv_grandmastertimeinaccuracy;
static int hf_ptp_v2_oe_tlv_subtype_c37238tlv_networktimeinaccuracy;
static int hf_ptp_v2_oe_tlv_subtype_c37238tlv_reserved;

/* Additional Fields for IEEE_C37_238-2017 TLV (OE TLV subtype) */
static int hf_ptp_v2_oe_tlv_subtype_c372382017tlv_reserved;
static int hf_ptp_v2_oe_tlv_subtype_c37238tlv_totaltimeinaccuracy;

/* Fields for SMPTE TLV (OE TLV subtype) */
static int hf_ptp_v2_oe_tlv_smpte_subtype;
static int hf_ptp_v2_oe_tlv_subtype_smpte_data;
static int hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate;
static int hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate_numerator;
static int hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate_denominator;
static int hf_ptp_v2_oe_tlv_subtype_smpte_masterlockingstatus;
static int hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags;
static int hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags_drop;
static int hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags_color;
static int hf_ptp_v2_oe_tlv_subtype_smpte_currentlocaloffset;
static int hf_ptp_v2_oe_tlv_subtype_smpte_jumpseconds;
static int hf_ptp_v2_oe_tlv_subtype_smpte_timeofnextjump;
static int hf_ptp_v2_oe_tlv_subtype_smpte_timeofnextjam;
static int hf_ptp_v2_oe_tlv_subtype_smpte_timeofpreviousjam;
static int hf_ptp_v2_oe_tlv_subtype_smpte_previousjamlocaloffset;
static int hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving;
static int hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_current;
static int hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_next;
static int hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_previous;
static int hf_ptp_v2_oe_tlv_subtype_smpte_leapsecondjump;
static int hf_ptp_v2_oe_tlv_subtype_smpte_leapsecondjump_change;
/* Fields for the ALTERNATE_TIME_OFFSET_INDICATOR TLV */
static int hf_ptp_v2_atoi_tlv_keyfield;
static int hf_ptp_v2_atoi_tlv_currentoffset;
static int hf_ptp_v2_atoi_tlv_jumpseconds;
static int hf_ptp_v2_atoi_tlv_timeofnextjump;
static int hf_ptp_v2_atoi_tlv_displayname;
static int hf_ptp_v2_atoi_tlv_displayname_length;
/* Field for the PATH TRACE TLV */
static int hf_ptp_v2_an_tlv_pathsequence;

/* Fields for an undissected TLV */
static int hf_ptp_v2_an_tlv_data;

/* Fields for PTP_Sync AND PTP_DelayRequest (=sdr) messages */
/* static int hf_ptp_v2_sdr_origintimestamp; */  /* Field for seconds & nanoseconds */
static int hf_ptp_v2_sdr_origintimestamp_seconds;
static int hf_ptp_v2_sdr_origintimestamp_nanoseconds;
static int hf_ptp_v2_sync_reserved;


/* Fields for PTP_Follow_Up (=fu) messages */
/* static int hf_ptp_v2_fu_preciseorigintimestamp; */    /* Field for seconds & nanoseconds */
static int hf_ptp_v2_fu_preciseorigintimestamp_seconds;
static int hf_ptp_v2_fu_preciseorigintimestamp_nanoseconds;
static int hf_ptp_v2_fu_preciseorigintimestamp_32bit;
/* Fields for the Follow_Up Information TLV */
static int hf_ptp_as_fu_tlv_tlvtype;
static int hf_ptp_as_fu_tlv_lengthfield;
static int hf_ptp_as_fu_tlv_organization_id;
static int hf_ptp_as_fu_tlv_organization_subtype;
static int hf_ptp_as_fu_tlv_cumulative_scaled_rate_offset;
static int hf_ptp_as_fu_tlv_cumulative_rate_ratio; /* Remove scale and offset from above */
static int hf_ptp_as_fu_tlv_gm_base_indicator;
static int hf_ptp_as_fu_tlv_last_gm_phase_change;
static int hf_ptp_as_fu_tlv_scaled_last_gm_freq_change;

/* Fields for PTP_DelayResponse (=dr) messages */
/* static int hf_ptp_v2_dr_receivetimestamp; */ /* Field for seconds & nanoseconds */
static int hf_ptp_v2_dr_receivetimestamp_seconds;
static int hf_ptp_v2_dr_receivetimestamp_nanoseconds;
static int hf_ptp_v2_dr_requestingportidentity;
static int hf_ptp_v2_dr_requestingsourceportid;


/* Fields for PTP_PDelayRequest (=pdrq) messages */
/* static int hf_ptp_v2_pdrq_origintimestamp; */ /* Field for seconds & nanoseconds */
static int hf_ptp_v2_pdrq_origintimestamp_seconds;
static int hf_ptp_v2_pdrq_origintimestamp_nanoseconds;


/* Fields for PTP_PDelayResponse (=pdrs) messages */
/* static int hf_ptp_v2_pdrs_requestreceipttimestamp; */ /* Field for seconds & nanoseconds */
static int hf_ptp_v2_pdrs_requestreceipttimestamp_seconds;
static int hf_ptp_v2_pdrs_requestreceipttimestamp_nanoseconds;
static int hf_ptp_v2_pdrs_requestingportidentity;
static int hf_ptp_v2_pdrs_requestingsourceportid;


/* Fields for PTP_PDelayResponseFollowUp (=pdfu) messages */
/* static int hf_ptp_v2_pdfu_responseorigintimestamp; */ /* Field for seconds & nanoseconds */
static int hf_ptp_v2_pdfu_responseorigintimestamp_seconds;
static int hf_ptp_v2_pdfu_responseorigintimestamp_nanoseconds;
static int hf_ptp_v2_pdfu_requestingportidentity;
static int hf_ptp_v2_pdfu_requestingsourceportid;


/* Fields for PTP_Signalling (=sig) messages */
static int hf_ptp_v2_sig_targetportidentity;
static int hf_ptp_v2_sig_targetportid;
static int hf_ptp_v2_sig_tlv_tlvType;
static int hf_ptp_v2_sig_tlv_lengthField;
static int hf_ptp_v2_sig_tlv_data;
static int hf_ptp_v2_sig_tlv_messageType;
static int hf_ptp_v2_sig_tlv_logInterMessagePeriod;
static int hf_ptp_v2_sig_tlv_logInterMessagePeriod_period;
static int hf_ptp_v2_sig_tlv_logInterMessagePeriod_rate;
static int hf_ptp_v2_sig_tlv_durationField;
static int hf_ptp_v2_sig_tlv_renewalInvited;

/* Fields for the Message Interval Request TLV */
static int hf_ptp_as_sig_tlv_tlvtype;
static int hf_ptp_as_sig_tlv_lengthfield;
static int hf_ptp_as_sig_tlv_organization_id;
static int hf_ptp_as_sig_tlv_organization_subtype;
static int hf_ptp_as_sig_tlv_link_delay_interval;
static int hf_ptp_as_sig_tlv_time_sync_interval;
static int hf_ptp_as_sig_tlv_announce_interval;
static int hf_ptp_as_sig_tlv_flags;
static int hf_ptp_as_sig_tlv_flags_comp_rate_ratio;
static int hf_ptp_as_sig_tlv_flags_comp_mean_link_delay;
static int hf_ptp_as_sig_tlv_flags_one_step_receive_capable;
static int hf_ptp_as_sig_tlv_gptp_capable_message_interval;

/* Fields for L1SYNC TLV */
static int hf_ptp_v2_sig_tlv_flags2;
static int hf_ptp_v2_sig_tlv_flags3;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_reserved;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_reserved;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_tcr;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_tcr;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_rcr;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_rcr;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_cr;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_cr;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_ope;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_ope;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_itc;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_itc;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_irc;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_irc;
static int hf_ptp_v2_sig_tlv_l1sync_flags2_ic;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_ic;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_tct;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_pov;
static int hf_ptp_v2_sig_tlv_l1sync_flags3_fov;
static int hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTx_ns;
static int hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTx_subns;
static int hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTxTimestamp_s;
static int hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTxTimestamp_ns;
static int hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTx_ns;
static int hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTx_subns;
static int hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTxTimestamp_s;
static int hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTxTimestamp_ns;

/* Fields for CERN White Rabbit TLV (OE TLV subtype) */
static int hf_ptp_v2_sig_oe_tlv_cern_subtype;
static int hf_ptp_v2_sig_oe_tlv_cern_wrMessageID;

static int hf_ptp_v2_sig_oe_tlv_cern_calSendPattern;
static int hf_ptp_v2_sig_oe_tlv_cern_calRety;
static int hf_ptp_v2_sig_oe_tlv_cern_calPeriod;
static int hf_ptp_v2_sig_oe_tlv_cern_deltaTx;
static int hf_ptp_v2_sig_oe_tlv_cern_deltaRx;

static int hf_ptp_v2_sig_oe_tlv_itut_subtype;
static int hf_ptp_v2_sig_tlv_interface_bit_period;
static int hf_ptp_v2_sig_tlv_numberbits_before_timestamp;
static int hf_ptp_v2_sig_tlv_numberbits_after_timestamp;

/* Fields for PTP_Management (=mm) messages */
static int hf_ptp_v2_mm_targetportidentity;
static int hf_ptp_v2_mm_targetportid;
static int hf_ptp_v2_mm_startingboundaryhops;
static int hf_ptp_v2_mm_boundaryhops;
static int hf_ptp_v2_mm_action;

/* management TLV */
static int hf_ptp_v2_mm_tlvType;
static int hf_ptp_v2_mm_lengthField;
static int hf_ptp_v2_mm_managementId;
static int hf_ptp_v2_mm_data;
/* Management dataField  */

static int hf_ptp_v2_mm_clockType;
static int hf_ptp_v2_mm_clockType_ordinaryClock;
static int hf_ptp_v2_mm_clockType_boundaryClock;
static int hf_ptp_v2_mm_clockType_p2p_transparentClock;
static int hf_ptp_v2_mm_clockType_e2e_transparentClock;
static int hf_ptp_v2_mm_clockType_managementNode;
static int hf_ptp_v2_mm_clockType_reserved;
static int hf_ptp_v2_mm_physicalLayerProtocol;
static int hf_ptp_v2_mm_physicalLayerProtocol_length;
static int hf_ptp_v2_mm_physicalAddressLength;
static int hf_ptp_v2_mm_physicalAddress;
static int hf_ptp_v2_mm_protocolAddress;
static int hf_ptp_v2_mm_protocolAddress_networkProtocol;
static int hf_ptp_v2_mm_protocolAddress_length;
static int hf_ptp_v2_mm_manufacturerIdentity;

static int hf_ptp_v2_mm_reserved;
static int hf_ptp_v2_mm_productDescription;
static int hf_ptp_v2_mm_productDescription_length;
static int hf_ptp_v2_mm_revisionData;
static int hf_ptp_v2_mm_revisionData_length;
static int hf_ptp_v2_mm_userDescription;
static int hf_ptp_v2_mm_userDescription_length;
static int hf_ptp_v2_mm_profileIdentity;
static int hf_ptp_v2_mm_pad;

static int hf_ptp_v2_mm_numberOfFaultRecords;
/* static int hf_ptp_v2_mm_faultRecord; */

static int hf_ptp_v2_mm_initializationKey;
static int hf_ptp_v2_mm_severityCode;
static int hf_ptp_v2_mm_faultRecordLength;
/* static int hf_ptp_v2_mm_faultTime; */
static int hf_ptp_v2_mm_faultTime_s;
static int hf_ptp_v2_mm_faultTime_ns;
static int hf_ptp_v2_mm_faultValue;
static int hf_ptp_v2_mm_faultName;
static int hf_ptp_v2_mm_faultName_length;
static int hf_ptp_v2_mm_faultValue_length;
static int hf_ptp_v2_mm_faultDescription;
static int hf_ptp_v2_mm_faultDescription_length;
static int hf_ptp_v2_mm_currentTime_s;
static int hf_ptp_v2_mm_currentTime_ns;
static int hf_ptp_v2_mm_clockAccuracy;
static int hf_ptp_v2_mm_priority1;
static int hf_ptp_v2_mm_priority2;
static int hf_ptp_v2_mm_dds_SO;
static int hf_ptp_v2_mm_TSC;
static int hf_ptp_v2_mm_numberPorts;
static int hf_ptp_v2_mm_clockclass;
static int hf_ptp_v2_mm_clockaccuracy;
static int hf_ptp_v2_mm_clockvariance;
static int hf_ptp_v2_mm_clockidentity;
static int hf_ptp_v2_mm_domainNumber;
static int hf_ptp_v2_mm_SO;
static int hf_ptp_v2_mm_stepsRemoved;
static int hf_ptp_v2_mm_parentIdentity;
static int hf_ptp_v2_mm_parentPort;
static int hf_ptp_v2_mm_parentStats;
static int hf_ptp_v2_mm_observedParentOffsetScaledLogVariance;
static int hf_ptp_v2_mm_observedParentClockPhaseChangeRate;
static int hf_ptp_v2_mm_grandmasterPriority1;
static int hf_ptp_v2_mm_grandmasterPriority2;
static int hf_ptp_v2_mm_grandmasterclockclass;
static int hf_ptp_v2_mm_grandmasterclockaccuracy;
static int hf_ptp_v2_mm_grandmasterclockvariance;
static int hf_ptp_v2_mm_grandmasterIdentity;
static int hf_ptp_v2_mm_currentUtcOffset;
static int hf_ptp_v2_mm_LI_61;
static int hf_ptp_v2_mm_LI_59;
static int hf_ptp_v2_mm_UTCV;
static int hf_ptp_v2_mm_PTP;
static int hf_ptp_v2_mm_TTRA;
static int hf_ptp_v2_mm_FTRA;
static int hf_ptp_v2_mm_timesource;
static int hf_ptp_v2_mm_offset_ns;
static int hf_ptp_v2_mm_pathDelay_ns;
static int hf_ptp_v2_mm_offset_subns;
static int hf_ptp_v2_mm_pathDelay_subns;
static int hf_ptp_v2_mm_PortNumber;
static int hf_ptp_v2_mm_portState;
static int hf_ptp_v2_mm_logMinDelayReqInterval;
static int hf_ptp_v2_mm_peerMeanPathDelay_ns;
static int hf_ptp_v2_mm_peerMeanPathDelay_subns;
static int hf_ptp_v2_mm_logAnnounceInterval;
static int hf_ptp_v2_mm_announceReceiptTimeout;
static int hf_ptp_v2_mm_logSyncInterval;
static int hf_ptp_v2_mm_delayMechanism;
static int hf_ptp_v2_mm_logMinPdelayReqInterval;
static int hf_ptp_v2_mm_versionNumber;
static int hf_ptp_v2_mm_primaryDomain;
static int hf_ptp_v2_mm_faultyFlag;
static int hf_ptp_v2_mm_managementErrorId;
static int hf_ptp_v2_mm_displayData;
static int hf_ptp_v2_mm_displayData_length;
static int hf_ptp_v2_mm_ucEN;
static int hf_ptp_v2_mm_ptEN;
static int hf_ptp_v2_mm_atEN;
static int hf_ptp_v2_mm_keyField;
static int hf_ptp_v2_mm_displayName;
static int hf_ptp_v2_mm_displayName_length;
static int hf_ptp_v2_mm_maxKey;
static int hf_ptp_v2_mm_currentOffset;
static int hf_ptp_v2_mm_jumpSeconds;
static int hf_ptp_v2_mm_nextjumpSeconds;
static int hf_ptp_v2_mm_logAlternateMulticastSyncInterval;
static int hf_ptp_v2_mm_numberOfAlternateMasters;
static int hf_ptp_v2_mm_transmitAlternateMulticastSync;

/* Fields for analysis code*/
static int hf_ptp_v2_analysis_sync_to_followup;
static int hf_ptp_v2_analysis_followup_to_sync;
static int hf_ptp_v2_analysis_pdelayreq_to_pdelayres;
static int hf_ptp_v2_analysis_pdelayres_to_pdelayreq;
static int hf_ptp_v2_analysis_pdelayres_to_pdelayfup;
static int hf_ptp_v2_analysis_pdelayfup_to_pdelayres;
static int hf_ptp_v2_analysis_sync_timestamp;
static int hf_ptp_v2_analysis_sync_timestamp_seconds;
static int hf_ptp_v2_analysis_sync_timestamp_nanoseconds;
static int hf_ptp_v2_analysis_sync_period;
static int hf_ptp_v2_analysis_sync_rateRatio;
static int hf_ptp_v2_analysis_sync_rateRatio_ppm;
static int hf_ptp_v2_analysis_pdelay_mpd_unscaled;
static int hf_ptp_v2_analysis_pdelay_mpd_unscaled_seconds;
static int hf_ptp_v2_analysis_pdelay_mpd_unscaled_nanoseconds;
static int hf_ptp_v2_analysis_pdelay_mpd_scaled;
static int hf_ptp_v2_analysis_pdelay_period;
static int hf_ptp_v2_analysis_pdelay_neighRateRatio;
static int hf_ptp_v2_analysis_pdelay_neighRateRatio_ppm;

/* Initialize the subtree pointers */
static int ett_ptp_v2;
static int ett_ptp_v2_flags;
static int ett_ptp_v2_clockidentity;
static int ett_ptp_v2_correction;
static int ett_ptp_v2_time;
static int ett_ptp_v2_time2;
static int ett_ptp_v2_managementData;
static int ett_ptp_v2_clockType;
static int ett_ptp_v2_physicalLayerProtocol;
static int ett_ptp_v2_protocolAddress;
static int ett_ptp_v2_faultRecord;
static int ett_ptp_v2_ptptext;
static int ett_ptp_v2_timeInterval;
static int ett_ptp_v2_tlv;
static int ett_ptp_v2_tlv_log_period;
static int ett_ptp_v2_sig_l1sync_flags;
static int ett_ptp_as_sig_tlv_flags;
static int ett_ptp_oe_wr_flags;
static int ett_ptp_oe_smpte_data;
static int ett_ptp_oe_smpte_framerate;
static int ett_ptp_oe_smpte_timeaddress;
static int ett_ptp_oe_smpte_daylightsaving;
static int ett_ptp_oe_smpte_leapsecondjump;
static int ett_ptp_analysis_timestamp;
static int ett_ptp_analysis_mean_propagation_delay;

/* static int ett_ptp_v2_timesource;
static int ett_ptp_v2_priority; */
static int ett_ptp_v2_majorsdoid;

static expert_field ei_ptp_v2_msg_len_too_large;
static expert_field ei_ptp_v2_msg_len_too_small;
static expert_field ei_ptp_v2_sync_no_followup;
static expert_field ei_ptp_v2_sync_no_fup_tlv;
static expert_field ei_ptp_v2_followup_no_sync;
static expert_field ei_ptp_v2_pdreq_no_pdresp;
static expert_field ei_ptp_v2_pdresp_no_pdreq;
static expert_field ei_ptp_v2_pdresp_no_pdfup;
static expert_field ei_ptp_v2_pdresp_twostep;
static expert_field ei_ptp_v2_pdfup_no_pdresp;
static expert_field ei_ptp_v2_period_invalid;

/* END Definitions and fields for PTPv2 dissection. */

/*
 * Analysis
 *
 * The analysis code cannot access the internal data of the PTP participants and
 * therefore the values calculated are based on the capture timestamps.
 *
 */

/* Config for Analysis features */
static bool ptp_analyze_messages = true;

/* Definitions for Analysis features */
#define PTP_ANALYSIS_MAX_ALLOWED_DELTA_SECS 60

typedef struct ptp_frame_info_sync {
    uint32_t sync_frame_num;
    uint32_t fup_frame_num;
    bool sync_two_step;

    nstime_t sync_ts;

    uint64_t timestamp_s;
    uint32_t timestamp_ns;
    int64_t  correction_ns;
    uint16_t correction_subns;

    bool calculated_timestamp_valid;
    nstime_t calculated_timestamp;

    bool syncInterval_valid;
    double   syncInterval;

    bool syncRateRatio_valid;
    double   syncRateRatio;
    int32_t  syncRateRatio_ppm;
} ptp_frame_info_sync_t;

typedef struct ptp_frame_info_pdelay {
    uint32_t pdelay_req_frame_num;
    uint32_t pdelay_res_frame_num;
    uint32_t pdelay_fup_frame_num;
    bool pdelay_res_two_step;

    nstime_t pdelay_req_ts;

    uint64_t pdelay_req_recv_ts_s;
    uint32_t pdelay_req_recv_ts_ns;

    uint64_t pdelay_res_send_ts_s;
    uint32_t pdelay_res_send_ts_ns;

    nstime_t pdelay_res_ts;

    nstime_t mean_propagation_delay_unscaled;
    double   mean_propagation_delay_scaled;

    bool pdelayInterval_valid;
    double   pdelayInterval;

    bool neighborRateRatio_valid;
    double   neighborRateRatio;
    int32_t  neighborRateRatio_ppm;
} ptp_frame_info_pdelay_t;

typedef struct ptp_frame_info {
    uint8_t messagetype;
    union {
        ptp_frame_info_sync_t sync;
        ptp_frame_info_pdelay_t pdelay;
    };

    struct ptp_frame_info *prev;
    nstime_t ref_time;
} ptp_frame_info_t;

#define PTP_FRAME_INFO_SYNC_SEEN(fi) ((fi) != NULL && (fi)->messagetype == PTP_V2_SYNC_MESSAGE && (fi)->sync.sync_frame_num != 0)
#define PTP_FRAME_INFO_SYNC_COMPLETE(fi) ((fi) != NULL && (fi)->messagetype == PTP_V2_SYNC_MESSAGE && (fi)->sync.sync_frame_num != 0 && (fi)->sync.fup_frame_num != 0)
#define PTP_FRAME_INFO_PDELAY_REQ_SEEN(fi) ((fi) != NULL && (fi)->messagetype == PTP_V2_PEER_DELAY_REQ_MESSAGE && (fi)->pdelay.pdelay_req_frame_num != 0)
#define PTP_FRAME_INFO_PDELAY_COMPLETE(fi) ((fi) != NULL && (fi)->messagetype == PTP_V2_PEER_DELAY_REQ_MESSAGE && (fi)->pdelay.pdelay_req_frame_num != 0 && (fi)->pdelay.pdelay_res_frame_num != 0 && (fi)->pdelay.pdelay_fup_frame_num != 0)

typedef struct ptp_clock_info {
    wmem_map_t *frames;
} ptp_clock_info_t;

static wmem_map_t *ptp_clocks;

/*
 * PTP major ver    4 bit
 * PTP min ver      4 bit (shift!)
 * MajorSdoId       4 bit
 * MessageType      4 bit (shift!)
 * MinorSdoId       1 Byte
 * Domain           1 Byte
 * PortID           2 Byte
 * SeqID            2 Byte
 */
static uint64_t
calculate_frame_key(uint8_t ptp_major, uint8_t ptp_minor, uint8_t majorsdoid, uint8_t minorsdoid, uint8_t messagetype, uint8_t domain, uint16_t portid, uint16_t seqid)
{
    DISSECTOR_ASSERT(ptp_minor % 16 == 0);
    DISSECTOR_ASSERT(ptp_major <= 15);
    DISSECTOR_ASSERT(majorsdoid % 16 == 0);
    DISSECTOR_ASSERT(messagetype <= 15);

    uint64_t ret = (uint64_t)ptp_minor  << 56 | (uint64_t)ptp_major << 56 | (uint64_t)majorsdoid << 48 | (uint64_t)messagetype << 48 | (uint64_t)minorsdoid << 40 | (uint64_t)domain << 32 |
                  (uint64_t)portid     << 16 | (uint64_t)seqid;
    return ret;
}

static ptp_frame_info_t *
get_frame_info_and_opt_create(packet_info *pinfo, uint8_t ptp_major, uint8_t ptp_minor, uint8_t majorsdoid, uint8_t minorsdoid, uint8_t messagetype, uint8_t domain, uint64_t clockidentity, uint16_t portid, uint16_t seqid, bool create_missing)
{
    DISSECTOR_ASSERT(ptp_clocks != NULL);

    ptp_clock_info_t *clock_info = (ptp_clock_info_t *)wmem_map_lookup(ptp_clocks, GUINT_TO_POINTER(clockidentity));

    if (clock_info == NULL)
    {
        clock_info = wmem_new0(wmem_file_scope(), ptp_clock_info_t);
        clock_info->frames = NULL;
        wmem_map_insert(ptp_clocks, GUINT_TO_POINTER(clockidentity), clock_info);
    }

    if (clock_info->frames == NULL)
    {
        clock_info->frames = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    }

    uint64_t key2 = calculate_frame_key(ptp_major, ptp_minor, majorsdoid, minorsdoid, messagetype, domain, portid, seqid);
    ptp_frame_info_t *tmp = (ptp_frame_info_t *)wmem_map_lookup(clock_info->frames, GUINT_TO_POINTER(key2));

    if (tmp != NULL)
    {
        /* Is this a real match or did have wrapped the ptp seqid? */
        nstime_t delta_time;
        nstime_delta(&delta_time, &(pinfo->abs_ts), &(tmp->ref_time));
        double delta_secs = nstime_to_sec(&delta_time);

        if (fabs(delta_secs) > PTP_ANALYSIS_MAX_ALLOWED_DELTA_SECS)
        {
            /* Not our match! */
            tmp = NULL;
        }
    }

    if (tmp == NULL && create_missing)
    {
        tmp = wmem_new0(wmem_file_scope(), ptp_frame_info_t);
        tmp->prev = NULL;
        if (messagetype == PTP_V2_PEER_DELAY_REQ_MESSAGE) {
            tmp->pdelay.neighborRateRatio_valid = false;
        }
        wmem_map_insert(clock_info->frames, GUINT_TO_POINTER(key2), tmp);

        nstime_copy(&(tmp->ref_time), &(pinfo->abs_ts));
    }

    return tmp;
}

static ptp_frame_info_t *
create_frame_info(packet_info *pinfo, uint8_t ptp_major, uint8_t ptp_minor, uint8_t majorsdoid, uint8_t minorsdoid, uint8_t messagetype, uint8_t domain, uint64_t clockidentity, uint16_t portid, uint16_t seqid)
{
    ptp_frame_info_t *ret = get_frame_info_and_opt_create(pinfo, ptp_major, ptp_minor, majorsdoid, minorsdoid, messagetype, domain, clockidentity, portid, seqid, true);

    uint16_t seqid_prev = seqid == 0 ? UINT16_MAX : seqid - 1;
    ret->prev = get_frame_info_and_opt_create(pinfo, ptp_major, ptp_minor, majorsdoid, minorsdoid, messagetype, domain, clockidentity, portid, seqid_prev, false);

    return ret;
}


/* forward declaration of local functions for v1 and v2 */

static bool
is_ptp_v1(tvbuff_t *tvb);

static void
dissect_ptp_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static bool
is_ptp_v2(tvbuff_t *tvb);

static void
dissect_ptp_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool ptpv2_oE);

/**********************************************************/
/* Implementation of the functions                        */
/**********************************************************/


/* Code to dissect the packet */

static int
dissect_ptp_oE(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /* PTP over Ethernet only available with PTPv2 */
    dissect_ptp_v2(tvb, pinfo, tree, true);
    return tvb_captured_length(tvb);
}

static int
dissect_ptp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    if(is_ptp_v1(tvb))
        dissect_ptp_v1(tvb, pinfo, tree);
    else if(is_ptp_v2(tvb))
        dissect_ptp_v2(tvb, pinfo, tree, false);

    return tvb_captured_length(tvb);
}


/* Code to check if packet is PTPv1 */

static bool
is_ptp_v1(tvbuff_t *tvb)
{
    uint16_t version_ptp;

    version_ptp = tvb_get_ntohs(tvb, PTP_VERSIONPTP_OFFSET);

    if( version_ptp == 1) return true;
    else return false;
}


/* Code to check if packet is PTPv2 */

static bool
is_ptp_v2(tvbuff_t *tvb)
{
    uint8_t version_ptp;

    version_ptp = 0x0F & tvb_get_uint8(tvb, PTP_V2_VERSIONPTP_OFFSET);

    if( version_ptp == 2) return true;
    else return false;
}


/* Code to actually dissect the PTPv1 packets */

static void
dissect_ptp_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    uint8_t  ptp_control_field, ptp_mm_messagekey = 0;
    nstime_t ts;                /* time structure with seconds and nanoseconds */

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti, *flags_ti, *time_ti, *time2_ti;
    proto_tree *ptp_tree = NULL, *ptp_flags_tree, *ptp_time_tree, *ptp_time2_tree;

/* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PTPv1");


/* Get control field (what kind of message is this? (Sync, DelayReq, ...) */

    ptp_control_field = tvb_get_uint8 (tvb, PTP_CONTROLFIELD_OFFSET);
    /* MGMT packet? */
    if (ptp_control_field == PTP_MANAGEMENT_MESSAGE ){
        /* Get the managementMessageKey */
        ptp_mm_messagekey = tvb_get_uint8(tvb, PTP_MM_MANAGEMENTMESSAGEKEY_OFFSET);
    }

/* Create and set the string for "Info" column */
    switch(ptp_control_field){
        case PTP_SYNC_MESSAGE:{
            col_set_str(pinfo->cinfo, COL_INFO, "Sync Message");
            break;
        }
        case PTP_DELAY_REQ_MESSAGE:{
            col_set_str(pinfo->cinfo, COL_INFO, "Delay_Request Message");
            break;
        }
        case PTP_FOLLOWUP_MESSAGE:{
            col_set_str(pinfo->cinfo, COL_INFO, "Follow_Up Message");
            break;
        }
        case PTP_DELAY_RESP_MESSAGE:{
            col_set_str(pinfo->cinfo, COL_INFO, "Delay_Response Message");
            break;
        }
        case PTP_MANAGEMENT_MESSAGE:{
             col_add_fstr(pinfo->cinfo, COL_INFO, "Management Message (%s)",
                             val_to_str_ext(ptp_mm_messagekey,
                                            &ptp_managementMessageKey_infocolumn_vals_ext,
                                            "Unknown message key %u"));
            break;
        }
        default:{
            col_set_str(pinfo->cinfo, COL_INFO, "Unknown Message");
            break;
        }
    }

    if (tree) {

        /* create display subtree for the protocol */
        ti = proto_tree_add_item(tree, proto_ptp, tvb, 0, -1, ENC_NA);

        ptp_tree = proto_item_add_subtree(ti, ett_ptp);

        proto_tree_add_item(ptp_tree,
            hf_ptp_versionptp, tvb, PTP_VERSIONPTP_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_versionnetwork, tvb, PTP_VERSIONNETWORK_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_subdomain, tvb, PTP_SUBDOMAIN_OFFSET, 16, ENC_ASCII);

        proto_tree_add_item(ptp_tree,
            hf_ptp_messagetype, tvb, PTP_MESSAGETYPE_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_sourcecommunicationtechnology, tvb, PTP_SOURCECOMMUNICATIONTECHNOLOGY_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_sourceuuid, tvb, PTP_SOURCEUUID_OFFSET, 6, ENC_NA);

        proto_tree_add_item(ptp_tree,
            hf_ptp_sourceportid, tvb, PTP_SOURCEPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_sequenceid, tvb, PTP_SEQUENCEID_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_controlfield, tvb, PTP_CONTROLFIELD_OFFSET, 1, ENC_BIG_ENDIAN);

        /* Subtree for the flag-field */
        /* TODO: use proto_tree_add_bitmask_list() ? */
        flags_ti = proto_tree_add_item(ptp_tree,
            hf_ptp_flags, tvb, PTP_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        ptp_flags_tree = proto_item_add_subtree(flags_ti, ett_ptp_flags);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_flags_li61, tvb, PTP_FLAGS_LI61_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_flags_li59, tvb, PTP_FLAGS_LI59_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_flags_boundary_clock, tvb, PTP_FLAGS_BOUNDARY_CLOCK_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_flags_assist, tvb, PTP_FLAGS_ASSIST_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_flags_ext_sync, tvb, PTP_FLAGS_EXT_SYNC_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_flags_parent, tvb, PTP_FLAGS_PARENT_STATS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_flags_sync_burst, tvb, PTP_FLAGS_SYNC_BURST_OFFSET, 2, ENC_BIG_ENDIAN);

        /* The rest of the ptp-dissector depends on the control-field  */

        switch(ptp_control_field){
            case PTP_SYNC_MESSAGE:
            case PTP_DELAY_REQ_MESSAGE:{

                /* Subtree for the timestamp-field */
                ts.secs = tvb_get_ntohl(tvb, PTP_SDR_ORIGINTIMESTAMP_SECONDS_OFFSET);
                ts.nsecs =  tvb_get_ntohl(tvb, PTP_SDR_ORIGINTIMESTAMP_NANOSECONDS_OFFSET);
                if(tree){
                    time_ti = proto_tree_add_time(ptp_tree,
                                      hf_ptp_sdr_origintimestamp, tvb, PTP_SDR_ORIGINTIMESTAMP_OFFSET, 8, &ts);

                    ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

                    proto_tree_add_item(ptp_time_tree,
                            hf_ptp_sdr_origintimestamp_seconds, tvb,
                            PTP_SDR_ORIGINTIMESTAMP_SECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                    proto_tree_add_item(ptp_time_tree, hf_ptp_sdr_origintimestamp_nanoseconds, tvb,
                            PTP_SDR_ORIGINTIMESTAMP_NANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                }

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_epochnumber, tvb, PTP_SDR_EPOCHNUMBER_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_currentutcoffset, tvb, PTP_SDR_CURRENTUTCOFFSET_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_sdr_grandmastercommunicationtechnology, tvb,
                        PTP_SDR_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_grandmasterclockuuid, tvb, PTP_SDR_GRANDMASTERCLOCKUUID_OFFSET, 6, ENC_NA);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_grandmasterportid, tvb, PTP_SDR_GRANDMASTERPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_grandmastersequenceid, tvb, PTP_SDR_GRANDMASTERSEQUENCEID_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_grandmasterclockstratum, tvb,
                        PTP_SDR_GRANDMASTERCLOCKSTRATUM_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_sdr_grandmasterclockidentifier, tvb,
                        PTP_SDR_GRANDMASTERCLOCKIDENTIFIER_OFFSET, 4, ENC_ASCII);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_grandmasterclockvariance, tvb,
                        PTP_SDR_GRANDMASTERCLOCKVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_grandmasterpreferred, tvb, PTP_SDR_GRANDMASTERPREFERRED_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_sdr_grandmasterisboundaryclock, tvb,
                        PTP_SDR_GRANDMASTERISBOUNDARYCLOCK_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_syncinterval, tvb, PTP_SDR_SYNCINTERVAL_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_localclockvariance, tvb, PTP_SDR_LOCALCLOCKVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_localstepsremoved, tvb, PTP_SDR_LOCALSTEPSREMOVED_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_localclockstratum, tvb, PTP_SDR_LOCALCLOCKSTRATUM_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_localclockidentifier, tvb, PTP_SDR_LOCALCLOCKIDENTIFIER_OFFSET, 4, ENC_ASCII);

                proto_tree_add_item(ptp_tree, hf_ptp_sdr_parentcommunicationtechnology, tvb,
                        PTP_SDR_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_parentuuid, tvb, PTP_SDR_PARENTUUID_OFFSET, 6, ENC_NA);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_parentportfield, tvb, PTP_SDR_PARENTPORTFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_estimatedmastervariance, tvb,
                        PTP_SDR_ESTIMATEDMASTERVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_estimatedmasterdrift, tvb, PTP_SDR_ESTIMATEDMASTERDRIFT_OFFSET, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_sdr_utcreasonable, tvb, PTP_SDR_UTCREASONABLE_OFFSET, 1, ENC_BIG_ENDIAN);
                break;
            }
            case PTP_FOLLOWUP_MESSAGE:{
                proto_tree_add_item(ptp_tree,
                        hf_ptp_fu_associatedsequenceid, tvb, PTP_FU_ASSOCIATEDSEQUENCEID_OFFSET, 2, ENC_BIG_ENDIAN);

                /* Subtree for the timestamp-field */
                ts.secs = tvb_get_ntohl(tvb, PTP_FU_PRECISEORIGINTIMESTAMP_SECONDS_OFFSET);
                ts.nsecs = tvb_get_ntohl(tvb, PTP_FU_PRECISEORIGINTIMESTAMP_NANOSECONDS_OFFSET);
                if(tree){
                    time_ti = proto_tree_add_time(ptp_tree,
                            hf_ptp_fu_preciseorigintimestamp, tvb,
                            PTP_FU_PRECISEORIGINTIMESTAMP_OFFSET, 8, &ts);

                    ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

                    proto_tree_add_item(ptp_time_tree, hf_ptp_fu_preciseorigintimestamp_seconds, tvb,
                            PTP_FU_PRECISEORIGINTIMESTAMP_SECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                    proto_tree_add_item(ptp_time_tree, hf_ptp_fu_preciseorigintimestamp_nanoseconds, tvb,
                            PTP_FU_PRECISEORIGINTIMESTAMP_NANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                }
                break;
            }
            case PTP_DELAY_RESP_MESSAGE:{
                /* Subtree for the timestamp-field */
                ts.secs = tvb_get_ntohl(tvb, PTP_DR_DELAYRECEIPTTIMESTAMP_SECONDS_OFFSET);
                ts.nsecs = tvb_get_ntohl(tvb, PTP_DR_DELAYRECEIPTTIMESTAMP_NANOSECONDS_OFFSET);
                if(tree){
                    time_ti = proto_tree_add_time(ptp_tree,
                            hf_ptp_dr_delayreceipttimestamp, tvb,
                            PTP_DR_DELAYRECEIPTTIMESTAMP_OFFSET, 8, &ts);

                    ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

                    proto_tree_add_item(ptp_time_tree, hf_ptp_dr_delayreceipttimestamp_seconds, tvb,
                            PTP_DR_DELAYRECEIPTTIMESTAMP_SECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                    proto_tree_add_item(ptp_time_tree, hf_ptp_dr_delayreceipttimestamp_nanoseconds, tvb,
                            PTP_DR_DELAYRECEIPTTIMESTAMP_NANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                }

                proto_tree_add_item(ptp_tree, hf_ptp_dr_requestingsourcecommunicationtechnology, tvb,
                    PTP_DR_REQUESTINGSOURCECOMMUNICATIONTECHNOLOGY_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_dr_requestingsourceuuid, tvb, PTP_DR_REQUESTINGSOURCEUUID_OFFSET, 6, ENC_NA);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_dr_requestingsourceportid, tvb, PTP_DR_REQUESTINGSOURCEPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_dr_requestingsourcesequenceid, tvb,
                        PTP_DR_REQUESTINGSOURCESEQUENCEID_OFFSET, 2, ENC_BIG_ENDIAN);
                break;
            }
            case PTP_MANAGEMENT_MESSAGE:{
                proto_tree_add_item(ptp_tree, hf_ptp_mm_targetcommunicationtechnology, tvb,
                        PTP_MM_TARGETCOMMUNICATIONTECHNOLOGY_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_mm_targetuuid, tvb, PTP_MM_TARGETUUID_OFFSET, 6, ENC_NA);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_mm_targetportid, tvb, PTP_MM_TARGETPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_mm_startingboundaryhops, tvb, PTP_MM_STARTINGBOUNDARYHOPS_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_mm_boundaryhops, tvb, PTP_MM_BOUNDARYHOPS_OFFSET, 2, ENC_BIG_ENDIAN);


                proto_tree_add_item(ptp_tree,
                        hf_ptp_mm_managementmessagekey, tvb, PTP_MM_MANAGEMENTMESSAGEKEY_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                        hf_ptp_mm_parameterlength, tvb, PTP_MM_PARAMETERLENGTH_OFFSET, 2, ENC_BIG_ENDIAN);

                switch(ptp_mm_messagekey){
                    case PTP_MM_CLOCK_IDENTITY:{
                        proto_tree_add_item(ptp_tree,
                                hf_ptp_mm_clock_identity_clockcommunicationtechnology, tvb,
                                PTP_MM_CLOCK_IDENTITY_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_clock_identity_clockuuidfield, tvb,
                                PTP_MM_CLOCK_IDENTITY_CLOCKUUIDFIELD_OFFSET, 6, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_clock_identity_clockportfield, tvb,
                                PTP_MM_CLOCK_IDENTITY_CLOCKPORTFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_clock_identity_manufactureridentity, tvb,
                                PTP_MM_CLOCK_IDENTITY_MANUFACTURERIDENTITY_OFFSET, 48, ENC_NA);
                        break;
                    }
                    case PTP_MM_INITIALIZE_CLOCK:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_initialize_clock_initialisationkey, tvb,
                            PTP_MM_INITIALIZE_CLOCK_INITIALISATIONKEY_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_SET_SUBDOMAIN:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_set_subdomain_subdomainname, tvb,
                                PTP_MM_SET_SUBDOMAIN_SUBDOMAINNAME_OFFSET, 16, ENC_ASCII);
                        break;
                    }
                    case PTP_MM_DEFAULT_DATA_SET:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockcommunicationtechnology,
                                tvb, PTP_MM_DEFAULT_DATA_SET_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET,
                                 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockuuidfield, tvb,
                                PTP_MM_DEFAULT_DATA_SET_CLOCKUUIDFIELD_OFFSET, 6, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockportfield, tvb,
                                PTP_MM_DEFAULT_DATA_SET_CLOCKPORTFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockstratum, tvb,
                                PTP_MM_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockidentifier, tvb,
                                PTP_MM_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET, 4, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockvariance, tvb,
                                PTP_MM_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockfollowupcapable, tvb,
                                PTP_MM_DEFAULT_DATA_SET_CLOCKFOLLOWUPCAPABLE_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_preferred, tvb,
                                PTP_MM_DEFAULT_DATA_SET_PREFERRED_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_initializable, tvb,
                                PTP_MM_DEFAULT_DATA_SET_INITIALIZABLE_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_externaltiming, tvb,
                                PTP_MM_DEFAULT_DATA_SET_EXTERNALTIMING_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_isboundaryclock, tvb,
                                PTP_MM_DEFAULT_DATA_SET_ISBOUNDARYCLOCK_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_syncinterval, tvb,
                                PTP_MM_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_subdomainname, tvb,
                                PTP_MM_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET, 16, ENC_ASCII);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_numberports, tvb,
                                PTP_MM_DEFAULT_DATA_SET_NUMBERPORTS_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_numberforeignrecords, tvb,
                                PTP_MM_DEFAULT_DATA_SET_NUMBERFOREIGNRECORDS_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_UPDATE_DEFAULT_DATA_SET:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_clockstratum, tvb,
                                PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_clockidentifier, tvb,
                                PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET, 4, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_clockvariance, tvb,
                                PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_preferred, tvb,
                                PTP_MM_UPDATE_DEFAULT_DATA_SET_PREFERRED_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_syncinterval, tvb,
                                PTP_MM_UPDATE_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_subdomainname, tvb,
                                PTP_MM_UPDATE_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET, 16, ENC_ASCII);
                        break;
                    }
                    case PTP_MM_CURRENT_DATA_SET:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_current_data_set_stepsremoved, tvb,
                                PTP_MM_CURRENT_DATA_SET_STEPSREMOVED_OFFSET, 2, ENC_BIG_ENDIAN);

                        /* Subtree for offset from master */
                        ts.secs = tvb_get_ntohl(tvb, PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERSECONDS_OFFSET);

                        ts.nsecs = tvb_get_ntohl(tvb,
                                PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERNANOSECONDS_OFFSET);

                        if (ts.nsecs & 0x80000000) ts.nsecs = ts.nsecs & 0x7FFFFFFF;

                        if(tree){
                            time_ti = proto_tree_add_time(ptp_tree,
                                    hf_ptp_mm_current_data_set_offsetfrommaster, tvb,
                                    PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTER_OFFSET, 8, &ts);

                            ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

                            proto_tree_add_item(ptp_time_tree,
                                    hf_ptp_mm_current_data_set_offsetfrommasterseconds, tvb,
                                    PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_time_tree,
                                    hf_ptp_mm_current_data_set_offsetfrommasternanoseconds, tvb,
                                    PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                        }

                        /* Subtree for offset from master */
                        ts.secs = tvb_get_ntohl(tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYSECONDS_OFFSET);

                        ts.nsecs = tvb_get_ntohl(tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYNANOSECONDS_OFFSET);

                        if(tree){
                            time2_ti = proto_tree_add_time(ptp_tree,
                                    hf_ptp_mm_current_data_set_onewaydelay, tvb,
                                    PTP_MM_CURRENT_DATA_SET_ONEWAYDELAY_OFFSET, 8, &ts);

                            ptp_time2_tree = proto_item_add_subtree(time2_ti, ett_ptp_time2);

                            proto_tree_add_item(ptp_time2_tree, hf_ptp_mm_current_data_set_onewaydelayseconds,
                                    tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_time2_tree,
                                    hf_ptp_mm_current_data_set_onewaydelaynanoseconds,
                                    tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                        }
                        break;
                    }
                    case PTP_MM_PARENT_DATA_SET:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentcommunicationtechnology,
                                tvb, PTP_MM_PARENT_DATA_SET_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET,
                                1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentuuid, tvb,
                                PTP_MM_PARENT_DATA_SET_PARENTUUID_OFFSET, 6, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentportid, tvb,
                                PTP_MM_PARENT_DATA_SET_PARENTPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentlastsyncsequencenumber,
                                tvb, PTP_MM_PARENT_DATA_SET_PARENTLASTSYNCSEQUENCENUMBER_OFFSET,
                                2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentfollowupcapable, tvb,
                                PTP_MM_PARENT_DATA_SET_PARENTFOLLOWUPCAPABLE_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentexternaltiming, tvb,
                                PTP_MM_PARENT_DATA_SET_PARENTEXTERNALTIMING_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentvariance, tvb,
                                PTP_MM_PARENT_DATA_SET_PARENTVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentstats, tvb,
                                PTP_MM_PARENT_DATA_SET_PARENTSTATS_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_observedvariance, tvb,
                                PTP_MM_PARENT_DATA_SET_OBSERVEDVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_observeddrift, tvb,
                                PTP_MM_PARENT_DATA_SET_OBSERVEDDRIFT_OFFSET, 4, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_utcreasonable, tvb,
                                PTP_MM_PARENT_DATA_SET_UTCREASONABLE_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree,
                                hf_ptp_mm_parent_data_set_grandmastercommunicationtechnology,
                                tvb, PTP_MM_PARENT_DATA_SET_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET, 1,
                                ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasteruuidfield, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERUUIDFIELD_OFFSET, 6, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterportidfield, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERPORTIDFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterstratum, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERSTRATUM_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasteridentifier, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERIDENTIFIER_OFFSET, 4, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmastervariance, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterpreferred, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERPREFERRED_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterisboundaryclock, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERISBOUNDARYCLOCK_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmastersequencenumber, tvb,
                                PTP_MM_PARENT_DATA_SET_GRANDMASTERSEQUENCENUMBER_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_PORT_DATA_SET:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_returnedportnumber, tvb,
                                PTP_MM_PORT_DATA_SET_RETURNEDPORTNUMBER_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portstate, tvb,
                                PTP_MM_PORT_DATA_SET_PORTSTATE_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_lastsynceventsequencenumber, tvb,
                                PTP_MM_PORT_DATA_SET_LASTSYNCEVENTSEQUENCENUMBER_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_lastgeneraleventsequencenumber,
                                tvb, PTP_MM_PORT_DATA_SET_LASTGENERALEVENTSEQUENCENUMBER_OFFSET,
                                2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portcommunicationtechnology, tvb,
                                PTP_MM_PORT_DATA_SET_PORTCOMMUNICATIONTECHNOLOGY_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portuuidfield, tvb,
                                PTP_MM_PORT_DATA_SET_PORTUUIDFIELD_OFFSET, 6, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portidfield, tvb,
                                PTP_MM_PORT_DATA_SET_PORTIDFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_burstenabled, tvb,
                                PTP_MM_PORT_DATA_SET_BURSTENABLED_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_subdomainaddressoctets, tvb,
                                PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESSOCTETS_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_eventportaddressoctets, tvb,
                                PTP_MM_PORT_DATA_SET_EVENTPORTADDRESSOCTETS_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_generalportaddressoctets, tvb,
                                PTP_MM_PORT_DATA_SET_GENERALPORTADDRESSOCTETS_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_subdomainaddress, tvb,
                                PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESS_OFFSET, 4, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_eventportaddress, tvb,
                                PTP_MM_PORT_DATA_SET_EVENTPORTADDRESS_OFFSET, 2, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_generalportaddress, tvb,
                                PTP_MM_PORT_DATA_SET_GENERALPORTADDRESS_OFFSET, 2, ENC_NA);
                        break;
                    }
                    case PTP_MM_GLOBAL_TIME_DATA_SET:{
                        /* Subtree for local time */
                        ts.secs = tvb_get_ntohl(tvb, PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMESECONDS_OFFSET);

                        ts.nsecs = tvb_get_ntohl(tvb,
                                PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMENANOSECONDS_OFFSET);

                        if(tree){
                            time_ti = proto_tree_add_time(ptp_tree,
                                    hf_ptp_mm_global_time_data_set_localtime, tvb,
                                    PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIME_OFFSET, 8, &ts);

                            ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

                            proto_tree_add_item(ptp_time_tree,
                                    hf_ptp_mm_global_time_data_set_localtimeseconds, tvb,
                                    PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMESECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_time_tree,
                                    hf_ptp_mm_global_time_data_set_localtimenanoseconds,
                                    tvb, PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMENANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                        }

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_currentutcoffset, tvb,
                                PTP_MM_GLOBAL_TIME_DATA_SET_CURRENTUTCOFFSET_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_leap59, tvb,
                                PTP_MM_GLOBAL_TIME_DATA_SET_LEAP59_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_leap61, tvb,
                                PTP_MM_GLOBAL_TIME_DATA_SET_LEAP61_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_epochnumber, tvb,
                                PTP_MM_GLOBAL_TIME_DATA_SET_EPOCHNUMBER_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_global_time_properties_currentutcoffset,
                                tvb, PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_CURRENTUTCOFFSET_OFFSET,
                                2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_global_time_properties_leap59, tvb,
                                PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP59_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_update_global_time_properties_leap61, tvb,
                                PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP61_OFFSET, 1, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_get_foreign_data_set_recordkey, tvb,
                                PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_EPOCHNUMBER_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_GET_FOREIGN_DATA_SET:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_get_foreign_data_set_recordkey, tvb,
                                PTP_MM_GET_FOREIGN_DATA_SET_RECORDKEY_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_FOREIGN_DATA_SET:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_returnedportnumber, tvb,
                                PTP_MM_FOREIGN_DATA_SET_RETURNEDPORTNUMBER_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_returnedrecordnumber, tvb,
                                PTP_MM_FOREIGN_DATA_SET_RETURNEDRECORDNUMBER_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree,
                                hf_ptp_mm_foreign_data_set_foreignmastercommunicationtechnology,
                                tvb, PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERCOMMUNICATIONTECHNOLOGY_OFFSET, 1,
                                ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_foreignmasteruuidfield, tvb,
                                PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERUUIDFIELD_OFFSET, 6, ENC_NA);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_foreignmasterportidfield, tvb,
                                PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERPORTIDFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_foreignmastersyncs, tvb,
                                PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERSYNCS_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_SET_SYNC_INTERVAL:{
                        proto_tree_add_item(ptp_tree, hf_ptp_mm_set_sync_interval_syncinterval, tvb,
                                PTP_MM_SET_SYNC_INTERVAL_SYNCINTERVAL_OFFSET, 2, ENC_BIG_ENDIAN);
                        break;
                    }
                    case PTP_MM_SET_TIME:{
                        /* Subtree for local time */
                        ts.secs = tvb_get_ntohl(tvb, PTP_MM_SET_TIME_LOCALTIMESECONDS_OFFSET);

                        ts.nsecs = tvb_get_ntohl(tvb, PTP_MM_SET_TIME_LOCALTIMENANOSECONDS_OFFSET);

                        if(tree){
                            time_ti = proto_tree_add_time(ptp_tree, hf_ptp_mm_set_time_localtime, tvb,
                                    PTP_MM_SET_TIME_LOCALTIME_OFFSET, 8, &ts);

                            ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

                            proto_tree_add_item(ptp_time_tree, hf_ptp_mm_set_time_localtimeseconds, tvb,
                                    PTP_MM_SET_TIME_LOCALTIMESECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_time_tree, hf_ptp_mm_set_time_localtimenanoseconds,
                                    tvb, PTP_MM_SET_TIME_LOCALTIMENANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                        }
                        break;
                    }
                    default :{
                        /* - don't dissect any further. */
                        break;
                    }
                }
                break;
            }
            default :{
                /* Not a valid MessageType - can't dissect. */
                break;
            }
        }
    }
}


/* Code to dissect PTPText */
static void
dissect_ptp_v2_text(tvbuff_t *tvb, uint16_t *cur_offset, proto_tree *tree, int hf_ptp_v2_mm_ptptext, int hf_ptp_v2_mm_ptptext_length)
{
    uint8_t     length = 0;
    proto_item *ptptext_ti;
    proto_tree *ptptext_subtree;

    length = tvb_get_uint8 (tvb, *cur_offset);

    if (tree)
    {
        ptptext_ti = proto_tree_add_item(tree, hf_ptp_v2_mm_ptptext, tvb,
            *cur_offset+1, length, ENC_BIG_ENDIAN);

        ptptext_subtree = proto_item_add_subtree(ptptext_ti, ett_ptp_v2_ptptext);
        /* subtree */
        proto_tree_add_item(ptptext_subtree, hf_ptp_v2_mm_ptptext_length, tvb,
                            *cur_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptptext_subtree, hf_ptp_v2_mm_ptptext, tvb,
                            *cur_offset+1, length, ENC_ASCII|ENC_NA);

        *cur_offset = *cur_offset + length + 1;
    }
}

static void
dissect_ptp_v2_timeInterval(tvbuff_t *tvb, uint16_t *cur_offset, proto_tree *tree, const char* name, int hf_ptp_v2_timeInterval_ns, int hf_ptp_v2_timeInterval_subns)
{

    double      time_double;
    int64_t     time_ns;
    uint16_t    time_subns;
    proto_tree *ptptimeInterval_subtree;

    time_ns = tvb_get_ntoh64(tvb, *cur_offset);
    time_double = (1.0*time_ns) / 65536.0;
    time_ns = time_ns >> 16;
    time_subns = tvb_get_ntohs(tvb, *cur_offset+6);

    ptptimeInterval_subtree = proto_tree_add_subtree_format(tree, tvb, *cur_offset, 8,
        ett_ptp_v2_timeInterval, NULL, "%s: %f nanoseconds", name, time_double);

    proto_tree_add_int64(ptptimeInterval_subtree,
        hf_ptp_v2_timeInterval_ns, tvb, *cur_offset, 6, time_ns);

    proto_tree_add_double(ptptimeInterval_subtree,
        hf_ptp_v2_timeInterval_subns, tvb, *cur_offset+6, 2, (time_subns/65536.0));

    *cur_offset = *cur_offset + 8;
}

static void
dissect_ptp_v2_timetstamp(tvbuff_t *tvb, uint16_t *cur_offset, proto_tree *tree,
                          const char* name, int hf_ptp_v2_timestamp_s,
                          int hf_ptp_v2_timestamp_ns)
{
    int64_t     time_s;
    uint32_t    time_ns;
    proto_tree *ptptimestamp_subtree;

    time_s = tvb_get_ntoh48(tvb, *cur_offset);
    time_ns = tvb_get_ntohl(tvb, *cur_offset + 6);

    ptptimestamp_subtree = proto_tree_add_subtree_format(tree,
                                                         tvb,
                                                         *cur_offset,
                                                         10,
                                                         ett_ptp_v2_timeInterval,
                                                         NULL,
                                                         "%s: %" PRIu64 "%s%09" PRId32 " nanoseconds",
                                                         name, time_s, decimal_point, time_ns);

    proto_tree_add_uint64(ptptimestamp_subtree,
                          hf_ptp_v2_timestamp_s,
                          tvb,
                          *cur_offset,
                          6,
                          time_s);

    proto_tree_add_int(ptptimestamp_subtree,
                       hf_ptp_v2_timestamp_ns,
                       tvb,
                       *cur_offset + 6,
                       4,
                       time_ns);

    *cur_offset = *cur_offset + 10;
}

/* Code to actually dissect the PTPv2 packets */

static void
dissect_follow_up_tlv(tvbuff_t *tvb, proto_tree *ptp_tree)
{
    proto_item  *ti = NULL;
    int32_t scaled_rate = 0;
    /* There are TLV's to be processed */
    uint16_t tlv_length = tvb_get_ntohs(tvb, PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_LENGTHFIELD_OFFSET);

    proto_tree *ptp_tlv_tree = proto_tree_add_subtree(ptp_tree, tvb, PTP_AS_FU_TLV_INFORMATION_OFFSET,
                                                      tlv_length + PTP_AS_FU_TLV_ORGANIZATIONID_OFFSET,
                                                      ett_ptp_v2_tlv, NULL, "Follow Up information TLV");

    proto_tree_add_item(ptp_tlv_tree, hf_ptp_as_fu_tlv_tlvtype, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(ptp_tlv_tree, hf_ptp_as_fu_tlv_lengthfield, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_LENGTHFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(ptp_tlv_tree, hf_ptp_as_fu_tlv_organization_id, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_ORGANIZATIONID_OFFSET, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item(ptp_tlv_tree, hf_ptp_as_fu_tlv_organization_subtype, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_ORGANIZATIONSUBTYPE_OFFSET, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item_ret_int(ptp_tlv_tree, hf_ptp_as_fu_tlv_cumulative_scaled_rate_offset, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_CUMULATIVESCALEDRATEOFFSET_OFFSET, 4, ENC_BIG_ENDIAN, &scaled_rate);

    // The cumulative scaled rate offset is (rateRatio - 1.0) * 2^41
    ti = proto_tree_add_double(ptp_tlv_tree, hf_ptp_as_fu_tlv_cumulative_rate_ratio, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_CUMULATIVESCALEDRATEOFFSET_OFFSET, 4, 1.0 + ((double) scaled_rate / (UINT64_C(1) << 41)));
    proto_item_set_generated(ti);

    proto_tree_add_item(ptp_tlv_tree, hf_ptp_as_fu_tlv_gm_base_indicator, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_GMTIMEBASEINDICATOR_OFFSET, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(ptp_tlv_tree, hf_ptp_as_fu_tlv_last_gm_phase_change, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_LASTGMPHASECHANGE_OFFSET, 12, ENC_NA);

    proto_tree_add_item(ptp_tlv_tree, hf_ptp_as_fu_tlv_scaled_last_gm_freq_change, tvb,
                        PTP_AS_FU_TLV_INFORMATION_OFFSET + PTP_AS_FU_TLV_SCALEDLASTGMFREQCHANGE_OFFSET, 4, ENC_BIG_ENDIAN);
}

static void
dissect_ptp_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, bool ptpv2_oE)
{
    uint8_t ptp_v2_majorsdoid;
    uint8_t ptp_v2_messageid;
    uint8_t ptp_v2_ver = 0;
    uint8_t ptp_v2_minorver = 0;
    uint8_t ptp_v2_domain = 0;
    uint8_t ptp_v2_minorsdoid = 0;
    uint64_t ptp_v2_correction = 0;
    uint64_t ptp_v2_clockid = 0;
    uint16_t ptp_v2_sourceportid = 0;
    uint16_t ptp_v2_seqid = 0;
    uint64_t ptp_v2_clockidref = 0;
    uint16_t ptp_v2_sourceportidref = 0;

    uint64_t timeStamp;
    uint16_t msg_len;
    uint16_t ptp_v2_flags;
    uint16_t temp;
    const char *manuf_name;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item  *ti = NULL, *msg_len_item = NULL, *flags_ti, *clockidentity_ti,
                *managementData_ti, *clockType_ti, *protocolAddress_ti, *ti_root = NULL;
    proto_tree  *ptp_tree = NULL, *ptp_flags_tree, *ptp_clockidentity_tree,
                *ptp_managementData_tree, *ptp_clockType_tree, *ptp_protocolAddress_tree;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PTPv2");

    /* Get majorSdoId bit to determine whether this is an AS packet or not */
    ptp_v2_majorsdoid = 0xF0 & tvb_get_uint8 (tvb, PTP_V2_MAJORSDOID_MESSAGE_TYPE_OFFSET);

    // 802.1as is indicated by Ethernet and a certain transport specific bit.
    bool is_802_1as = (ptp_v2_majorsdoid & PTP_V2_MAJORSDOID_ASPACKET_BITMASK) && (ptpv2_oE == true);

    /* Get control field (what kind of message is this? (Sync, DelayReq, ...) */
    ptp_v2_messageid = 0x0F & tvb_get_uint8 (tvb, PTP_V2_MAJORSDOID_MESSAGE_TYPE_OFFSET);

    msg_len = tvb_get_ntohs(tvb, PTP_V2_MESSAGE_LENGTH_OFFSET);

    ptp_v2_flags = tvb_get_uint16(tvb, PTP_V2_FLAGS_OFFSET, ENC_BIG_ENDIAN);

    if (ptp_analyze_messages)
    {
        ptp_v2_ver = 0x0F & tvb_get_uint8(tvb, PTP_V2_VERSIONPTP_OFFSET);
        ptp_v2_minorver = 0xF0 & tvb_get_uint8(tvb, PTP_V2_MINORVERSIONPTP_OFFSET);
        ptp_v2_domain = tvb_get_uint8(tvb, PTP_V2_DOMAIN_NUMBER_OFFSET);
        ptp_v2_minorsdoid = tvb_get_uint8(tvb, PTP_V2_MINORSDOID_OFFSET);
        ptp_v2_clockid = tvb_get_uint64(tvb, PTP_V2_CLOCKIDENTITY_OFFSET, ENC_BIG_ENDIAN);
        ptp_v2_sourceportid = tvb_get_uint16(tvb, PTP_V2_SOURCEPORTID_OFFSET, ENC_BIG_ENDIAN);
        ptp_v2_seqid = tvb_get_uint16(tvb, PTP_V2_SEQUENCEID_OFFSET, ENC_BIG_ENDIAN);
        ptp_v2_correction = tvb_get_uint64(tvb, PTP_V2_CORRECTION_OFFSET, ENC_BIG_ENDIAN);

        switch (ptp_v2_messageid)
        {
        case PTP_V2_PEER_DELAY_RESP_MESSAGE:
            ptp_v2_clockidref = tvb_get_uint64(tvb, PTP_V2_PDRS_REQUESTINGPORTIDENTITY_OFFSET, ENC_BIG_ENDIAN);
            ptp_v2_sourceportidref = tvb_get_uint16(tvb, PTP_V2_PDRS_REQUESTINGSOURCEPORTID_OFFSET, ENC_BIG_ENDIAN);
            break;
        case PTP_V2_PEER_DELAY_FOLLOWUP_MESSAGE:
            ptp_v2_clockidref = tvb_get_uint64(tvb, PTP_V2_PDFU_REQUESTINGPORTIDENTITY_OFFSET, ENC_BIG_ENDIAN);
            ptp_v2_sourceportidref = tvb_get_uint16(tvb, PTP_V2_PDFU_REQUESTINGSOURCEPORTID_OFFSET, ENC_BIG_ENDIAN);
            break;
        }

        if (!(pinfo->fd->visited))
        {
            ptp_frame_info_t *frame_info = NULL;
            switch (ptp_v2_messageid)
            {
            case PTP_V2_SYNC_MESSAGE:
                frame_info = create_frame_info(pinfo, ptp_v2_ver, ptp_v2_minorver, ptp_v2_majorsdoid, ptp_v2_minorsdoid, PTP_V2_SYNC_MESSAGE, ptp_v2_domain, ptp_v2_clockid, ptp_v2_sourceportid, ptp_v2_seqid);
                frame_info->messagetype = PTP_V2_SYNC_MESSAGE;
                frame_info->sync.sync_two_step = (ptp_v2_flags & PTP_V2_FLAGS_TWO_STEP_BITMASK) == PTP_V2_FLAGS_TWO_STEP_BITMASK;
                frame_info->sync.sync_ts = pinfo->abs_ts;
                frame_info->sync.sync_frame_num = pinfo->num;

                if (!frame_info->sync.sync_two_step) {
                    /* In 1-step mode, the sync carries the followup information, so we set fup to sync */
                    frame_info->sync.fup_frame_num = pinfo->num;
                    frame_info->sync.timestamp_s = tvb_get_uint48(tvb, PTP_V2_FU_PRECISEORIGINTIMESTAMPSECONDS_OFFSET, ENC_BIG_ENDIAN);
                    frame_info->sync.timestamp_ns = tvb_get_uint32(tvb, PTP_V2_FU_PRECISEORIGINTIMESTAMPNANOSECONDS_OFFSET, ENC_BIG_ENDIAN);
                    frame_info->sync.correction_ns = ptp_v2_correction >> 16;
                    frame_info->sync.correction_subns = ptp_v2_correction % 16;
                }
                break;
            case PTP_V2_FOLLOWUP_MESSAGE:
                frame_info = create_frame_info(pinfo, ptp_v2_ver, ptp_v2_minorver, ptp_v2_majorsdoid, ptp_v2_minorsdoid, PTP_V2_SYNC_MESSAGE, ptp_v2_domain, ptp_v2_clockid, ptp_v2_sourceportid, ptp_v2_seqid);
                frame_info->messagetype = PTP_V2_SYNC_MESSAGE;
                frame_info->sync.fup_frame_num = pinfo->num;
                frame_info->sync.timestamp_s = tvb_get_uint48(tvb, PTP_V2_FU_PRECISEORIGINTIMESTAMPSECONDS_OFFSET, ENC_BIG_ENDIAN);
                frame_info->sync.timestamp_ns = tvb_get_uint32(tvb, PTP_V2_FU_PRECISEORIGINTIMESTAMPNANOSECONDS_OFFSET, ENC_BIG_ENDIAN);
                frame_info->sync.correction_ns = ptp_v2_correction >> 16;
                frame_info->sync.correction_subns = ptp_v2_correction % 16;
                break;
            case PTP_V2_PEER_DELAY_REQ_MESSAGE:
                frame_info = create_frame_info(pinfo, ptp_v2_ver, ptp_v2_minorver, ptp_v2_majorsdoid, ptp_v2_minorsdoid, PTP_V2_PEER_DELAY_REQ_MESSAGE, ptp_v2_domain, ptp_v2_clockid, ptp_v2_sourceportid, ptp_v2_seqid);
                frame_info->messagetype = PTP_V2_PEER_DELAY_REQ_MESSAGE;
                frame_info->pdelay.pdelay_req_frame_num = pinfo->num;
                frame_info->pdelay.pdelay_req_ts = pinfo->abs_ts;
                break;
            case PTP_V2_PEER_DELAY_RESP_MESSAGE:
                frame_info = create_frame_info(pinfo, ptp_v2_ver, ptp_v2_minorver, ptp_v2_majorsdoid, ptp_v2_minorsdoid, PTP_V2_PEER_DELAY_REQ_MESSAGE, ptp_v2_domain, ptp_v2_clockidref, ptp_v2_sourceportidref, ptp_v2_seqid);
                frame_info->messagetype = PTP_V2_PEER_DELAY_REQ_MESSAGE;
                frame_info->pdelay.pdelay_res_frame_num = pinfo->num;
                frame_info->pdelay.pdelay_res_two_step = (ptp_v2_flags & PTP_V2_FLAGS_TWO_STEP_BITMASK) == PTP_V2_FLAGS_TWO_STEP_BITMASK;
                frame_info->pdelay.pdelay_res_ts = pinfo->abs_ts;
                frame_info->pdelay.pdelay_req_recv_ts_s = tvb_get_uint48(tvb, PTP_V2_PDRS_REQUESTRECEIPTTIMESTAMPSECONDS_OFFSET, ENC_BIG_ENDIAN);
                frame_info->pdelay.pdelay_req_recv_ts_ns = tvb_get_uint32(tvb, PTP_V2_PDRS_REQUESTRECEIPTTIMESTAMPNANOSECONDS_OFFSET, ENC_BIG_ENDIAN);
                break;
            case PTP_V2_PEER_DELAY_FOLLOWUP_MESSAGE:
                frame_info = create_frame_info(pinfo, ptp_v2_ver, ptp_v2_minorver, ptp_v2_majorsdoid, ptp_v2_minorsdoid, PTP_V2_PEER_DELAY_REQ_MESSAGE, ptp_v2_domain, ptp_v2_clockidref, ptp_v2_sourceportidref, ptp_v2_seqid);
                frame_info->messagetype = PTP_V2_PEER_DELAY_REQ_MESSAGE;
                frame_info->pdelay.pdelay_fup_frame_num = pinfo->num;
                frame_info->pdelay.pdelay_res_send_ts_s = tvb_get_uint48(tvb, PTP_V2_PDFU_RESPONSEORIGINTIMESTAMPSECONDS_OFFSET, ENC_BIG_ENDIAN);
                frame_info->pdelay.pdelay_res_send_ts_ns = tvb_get_uint32(tvb, PTP_V2_PDFU_RESPONSEORIGINTIMESTAMPNANOSECONDS_OFFSET, ENC_BIG_ENDIAN);
                break;
            }

            if (frame_info != NULL) {
                p_add_proto_data(wmem_file_scope(), pinfo, proto_ptp, 0, frame_info);
            }

            if PTP_FRAME_INFO_SYNC_SEEN(frame_info) {

                if (PTP_FRAME_INFO_SYNC_COMPLETE(frame_info) && !frame_info->sync.calculated_timestamp_valid) {
                    /* calculate two step sync timestamp */

                    nstime_t ts = NSTIME_INIT_SECS_NSECS(frame_info->sync.timestamp_s, frame_info->sync.timestamp_ns);

                    /* we are ignoring subns */
                    int64_t corr_s  = frame_info->sync.correction_ns / NS_PER_S;
                    int32_t corr_ns = frame_info->sync.correction_ns % NS_PER_S;
                    nstime_t corr = NSTIME_INIT_SECS_NSECS(corr_s, corr_ns);

                    nstime_sum(&(frame_info->sync.calculated_timestamp), &(ts), &(corr));
                    frame_info->sync.calculated_timestamp_valid = true;
                }

                if PTP_FRAME_INFO_SYNC_SEEN(frame_info->prev) {
                    nstime_t delta_capture_ts;
                    nstime_delta(&delta_capture_ts, &(frame_info->sync.sync_ts), &(frame_info->prev->sync.sync_ts));

                    frame_info->sync.syncInterval = nstime_to_sec(&delta_capture_ts);
                    if (frame_info->sync.syncInterval > 0)
                        frame_info->sync.syncInterval_valid = true;

                    if (PTP_FRAME_INFO_SYNC_COMPLETE(frame_info->prev) && frame_info->sync.calculated_timestamp_valid && frame_info->prev->sync.calculated_timestamp_valid) {
                        nstime_t delta_sync_ts;
                        nstime_delta(&delta_sync_ts, &(frame_info->sync.calculated_timestamp), &(frame_info->prev->sync.calculated_timestamp));

                        if (frame_info->sync.syncInterval_valid) {
                            frame_info->sync.syncRateRatio = nstime_to_sec(&delta_sync_ts) / nstime_to_sec(&delta_capture_ts);
                            frame_info->sync.syncRateRatio_valid = true;
                            frame_info->sync.syncRateRatio_ppm =
                                (int32_t)((1.0 - frame_info->sync.syncRateRatio) * 1000 * 1000);
                        }
                    }
                }
            }

            if (PTP_FRAME_INFO_PDELAY_REQ_SEEN(frame_info) && PTP_FRAME_INFO_PDELAY_REQ_SEEN(frame_info->prev)) {
                nstime_t t4_delta;
                nstime_delta(&t4_delta, &frame_info->pdelay.pdelay_res_ts, &frame_info->prev->pdelay.pdelay_res_ts);

                frame_info->pdelay.pdelayInterval = nstime_to_sec(&t4_delta);
                if (frame_info->pdelay.pdelayInterval > 0)
                    frame_info->pdelay.pdelayInterval_valid = true;

                if (PTP_FRAME_INFO_PDELAY_COMPLETE(frame_info) && PTP_FRAME_INFO_PDELAY_COMPLETE(frame_info->prev)) {
                    /* lets calculate rate t3_delta / t4_delta */
                    nstime_t t3_delta;
                    nstime_t t3_curr = NSTIME_INIT_SECS_NSECS(frame_info->pdelay.pdelay_res_send_ts_s, frame_info->pdelay.pdelay_res_send_ts_ns);
                    nstime_t t3_prev = NSTIME_INIT_SECS_NSECS(frame_info->prev->pdelay.pdelay_res_send_ts_s, frame_info->prev->pdelay.pdelay_res_send_ts_ns);
                    nstime_delta(&t3_delta, &t3_curr, &t3_prev);

                    if (frame_info->pdelay.pdelayInterval_valid) {
                        frame_info->pdelay.neighborRateRatio = nstime_to_sec(&t3_delta) / nstime_to_sec(&t4_delta);
                        frame_info->pdelay.neighborRateRatio_valid = true;
                        frame_info->pdelay.neighborRateRatio_ppm =
                            (int32_t)((1.0 - frame_info->pdelay.neighborRateRatio) * 1000 * 1000);
                    }
                }
            }

            if PTP_FRAME_INFO_PDELAY_COMPLETE(frame_info) {
                /* lets calculate peer delay: T4 - T1 - (t3 - t2) */
                nstime_t t2 = NSTIME_INIT_SECS_NSECS(frame_info->pdelay.pdelay_req_recv_ts_s, frame_info->pdelay.pdelay_req_recv_ts_ns);
                nstime_t t3 = NSTIME_INIT_SECS_NSECS(frame_info->pdelay.pdelay_res_send_ts_s, frame_info->pdelay.pdelay_res_send_ts_ns);
                nstime_t peer_delta_t3_t2;
                nstime_delta(&peer_delta_t3_t2, &t3, &t2);

                nstime_delta(&frame_info->pdelay.mean_propagation_delay_unscaled, &(frame_info->pdelay.pdelay_res_ts), &(frame_info->pdelay.pdelay_req_ts));
                double delta_t4_t1 = nstime_to_sec(&(frame_info->pdelay.mean_propagation_delay_unscaled));
                nstime_subtract(&frame_info->pdelay.mean_propagation_delay_unscaled, &peer_delta_t3_t2);

                /* now take only 1/2 of it */
                frame_info->pdelay.mean_propagation_delay_unscaled.nsecs /= 2;
                if ((frame_info->pdelay.mean_propagation_delay_unscaled.secs % 2) == 1) {
                    frame_info->pdelay.mean_propagation_delay_unscaled.secs -= 1;
                    frame_info->pdelay.mean_propagation_delay_unscaled.nsecs += NS_PER_S / 2;
                }
                frame_info->pdelay.mean_propagation_delay_unscaled.secs /= 2;

                /* lets scale by neighborRateRatio. converted to the capture timestamp timescale. */
                if (frame_info->pdelay.neighborRateRatio_valid) {
                    double delta_t3_t2 = nstime_to_sec(&peer_delta_t3_t2);
                    frame_info->pdelay.mean_propagation_delay_scaled = 0.5 * (delta_t4_t1 - frame_info->pdelay.neighborRateRatio * delta_t3_t2);
                }
            }
        }
    }

    /* Extend  Info column with managementId */
    /* Create and set the string for "Info" column */
    if ( ptp_v2_messageid == PTP_V2_MANAGEMENT_MESSAGE )
    {
        uint16_t tlv_type;
        /* Get TLV Type */
        tlv_type = tvb_get_ntohs (tvb, PTP_V2_MM_TLV_TYPE_OFFSET);
        /* For management there are PTP_V2_TLV_TYPE_MANAGEMENT and PTP_V2_TLV_TYPE_MANAGEMENT_ERROR_STATUS TLVs */
        switch(tlv_type)
        {
            case PTP_V2_TLV_TYPE_MANAGEMENT:
            {
                uint16_t ptp_v2_mm_managementId;
                uint8_t ptp_v2_management_action;
                /* Get the managementId */
                ptp_v2_mm_managementId = tvb_get_ntohs(tvb, PTP_V2_MM_TLV_MANAGEMENTID_OFFSET);
                ptp_v2_management_action = 0x0F & tvb_get_uint8(tvb, PTP_V2_MM_ACTION_OFFSET);
                col_add_fstr(pinfo->cinfo, COL_INFO, "Management (%s) %s",
                    val_to_str_ext(ptp_v2_mm_managementId, &ptp_v2_managementID_infocolumn_vals_ext, "Unknown management Id %u"),
                    val_to_str(ptp_v2_management_action, ptp_v2_mm_action_vals, "Unknown Action %u"));
                break;
            }
            case PTP_V2_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
            {
                uint16_t ptp_v2_mm_managementId;
                /* Get the managementErrorId */
                ptp_v2_mm_managementId = tvb_get_ntohs(tvb, PTP_V2_MM_TLV_MANAGEMENTERRORID_OFFSET);
                col_add_fstr(pinfo->cinfo, COL_INFO, "Management Error Message (%s)",
                    val_to_str_ext(ptp_v2_mm_managementId, &ptp_v2_managementErrorId_vals_ext, "Unknown Error Id %u"));
                break;
            }
            default:
                col_add_str(pinfo->cinfo, COL_INFO,
                    val_to_str_ext(ptp_v2_messageid, &ptp_v2_messagetype_vals_ext, "Unknown PTP Message (%u)"));
                break;
        }
    }
    else
    {
        col_add_str(pinfo->cinfo, COL_INFO, val_to_str_ext(ptp_v2_messageid, &ptp_v2_messagetype_vals_ext, "Unknown PTP Message (%u)"));
        if (ptp_v2_messageid == PTP_V2_SIGNALLING_MESSAGE)
        {
            uint32_t tlv_offset;
            uint16_t tlv_type;
            uint32_t org_id;
            uint32_t subtype;
            uint16_t tlv_length;
            uint16_t wr_messageId;

            tlv_offset = PTP_V2_SIG_TLV_START;

            while (tlv_offset + PTP_V2_SIG_TLV_LENGTH_LEN + PTP_V2_SIG_TLV_TYPE_LEN <= msg_len)
            {
                tlv_length   = tvb_get_ntohs(tvb, tlv_offset + PTP_V2_SIG_TLV_LENGTH_OFFSET);
                tlv_type     = tvb_get_ntohs(tvb, tlv_offset + PTP_V2_SIG_TLV_TYPE_OFFSET);

                if (tlv_type == PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION)
                {
                        org_id = tvb_get_ntoh24(tvb, tlv_offset + PTP_V2_SIG_TLV_ORGANIZATIONID_OFFSET);
                        subtype = tvb_get_ntoh24(tvb, tlv_offset + PTP_V2_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET);

                        if (org_id == OUI_CERN && subtype == PTP_V2_OE_ORG_CERN_SUBTYPE_WR_TLV)
                        {
                            col_append_str(pinfo->cinfo, COL_INFO, " WR ");
                            wr_messageId = tvb_get_ntohs(tvb, tlv_offset + PTP_V2_SIG_TLV_WRTLV_MESSAGEID_OFFSET);
                            col_append_str(pinfo->cinfo,
                                           COL_INFO,
                                           val_to_str(wr_messageId,
                                                      ptp_v2_org_cern_wrMessageID_vals,
                                                      "Unknown PTP WR Message (%u)"
                                                      )
                                          );
                        }
                }
                if (tlv_type == PTP_V2_TLV_TYPE_L1_SYNC) {
                        uint16_t l1sync_flags;

                        col_append_str(pinfo->cinfo, COL_INFO, " PTP L1 SYNC");
                        l1sync_flags = tvb_get_ntohs(tvb, tlv_offset + PTP_V2_SIG_TLV_L1SYNC_FLAGS_OFFSET);

                        if (l1sync_flags & PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_OPE_BITMASK) {
                                col_append_str(pinfo->cinfo, COL_INFO, " ext");
                        }
                }
                tlv_offset += PTP_V2_SIG_TLV_TYPE_LEN +
                              PTP_V2_SIG_TLV_LENGTH_LEN +
                              tlv_length;
            }
        }
    }

   if (tree) {

        ti_root = proto_tree_add_item(tree, proto_ptp, tvb, 0, -1, ENC_NA);

        ptp_tree = proto_item_add_subtree(ti_root, ett_ptp_v2);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_majorsdoid, tvb, PTP_V2_MAJORSDOID_MESSAGE_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_messagetype, tvb, PTP_V2_MAJORSDOID_MESSAGE_TYPE_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_minorversionptp, tvb, PTP_V2_MINORVERSIONPTP_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_versionptp, tvb, PTP_V2_VERSIONPTP_OFFSET, 1, ENC_BIG_ENDIAN);

        msg_len_item = proto_tree_add_item(ptp_tree,
            hf_ptp_v2_messagelength, tvb, PTP_V2_MESSAGE_LENGTH_OFFSET, 2, ENC_BIG_ENDIAN);
   }

   /*
    * Sanity-check the message length.
    */
   if (msg_len > tvb_reported_length(tvb)) {
       /* Bogus message length - runs past the end of the packet */
       expert_add_info(pinfo, msg_len_item, &ei_ptp_v2_msg_len_too_large);
       msg_len = tvb_reported_length(tvb);
   } else if (msg_len < PTP_V2_MESSAGE_LENGTH_OFFSET + 2) {
       /* Bogus message length - not long enough to include the message length field */
       expert_add_info(pinfo, msg_len_item, &ei_ptp_v2_msg_len_too_small);
       return;
   } else {
       /*
        * Set the length of this tvbuff to the message length, chopping
        * off extra data.
        */
       set_actual_length(tvb, msg_len);
       proto_item_set_len(ti_root, msg_len);
   }

   if (tree) {
        ptp_frame_info_t *frame_info = (ptp_frame_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ptp, 0);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_domainnumber, tvb, PTP_V2_DOMAIN_NUMBER_OFFSET, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_minorsdoid, tvb, PTP_V2_MINORSDOID_OFFSET, 1, ENC_BIG_ENDIAN);

        flags_ti = proto_tree_add_item(ptp_tree,
            hf_ptp_v2_flags, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        ptp_flags_tree = proto_item_add_subtree(flags_ti, ett_ptp_v2_flags);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_security, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_specific2, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_specific1, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_unicast, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_twostep, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_alternatemaster, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_synchronizationUncertain, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_frequencytraceable, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_timetraceable, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_ptptimescale, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_utcoffsetvalid, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_li59, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_flags_tree,
            hf_ptp_v2_flags_li61, tvb, PTP_V2_FLAGS_OFFSET, 2, ENC_BIG_ENDIAN);

        temp = PTP_V2_CORRECTIONNS_OFFSET;

        dissect_ptp_v2_timeInterval(tvb, &temp, ptp_tree, "correctionField", hf_ptp_v2_correction, hf_ptp_v2_correctionsubns);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_messagetypespecific, tvb, PTP_V2_MESSAGE_TYPE_SPECIFIC_OFFSET, 4, ENC_BIG_ENDIAN);

        clockidentity_ti = proto_tree_add_item(ptp_tree,
            hf_ptp_v2_clockidentity, tvb, PTP_V2_CLOCKIDENTITY_OFFSET, 8, ENC_BIG_ENDIAN);

        /* EUI-64: vendor ID | 0xFF - 0xFE | card ID */
        if (tvb_get_ntohs(tvb, PTP_V2_CLOCKIDENTITY_OFFSET + 3) == 0xFFFE) {
            ptp_clockidentity_tree = proto_item_add_subtree(clockidentity_ti, ett_ptp_v2_clockidentity);

            manuf_name = tvb_get_manuf_name(tvb, PTP_V2_CLOCKIDENTITY_OFFSET);
            proto_tree_add_bytes_format_value(ptp_clockidentity_tree, hf_ptp_v2_clockidentity_manuf,
                tvb, PTP_V2_CLOCKIDENTITY_OFFSET, 3, NULL, "%s", manuf_name);
        }

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_sourceportid, tvb, PTP_V2_SOURCEPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

        proto_tree_add_item(ptp_tree,
            hf_ptp_v2_sequenceid, tvb, PTP_V2_SEQUENCEID_OFFSET, 2, ENC_BIG_ENDIAN);

        //The controlField in the IEEE 802.1AS is 0 for all messages(they have minorVersionPTP set to 1)
        if (tvb_get_ntohs(tvb, PTP_V2_MINORVERSIONPTP_OFFSET) == 1) {
            proto_tree_add_item(ptp_tree,
                hf_ptp_v2_controlfield_default, tvb, PTP_V2_CONTROLFIELD_OFFSET, 1, ENC_BIG_ENDIAN);
        }
        else {
            proto_tree_add_item(ptp_tree,
                hf_ptp_v2_controlfield, tvb, PTP_V2_CONTROLFIELD_OFFSET, 1, ENC_BIG_ENDIAN);
        }

        int logmsgperiod;
        ti = proto_tree_add_item_ret_int(ptp_tree,
            hf_ptp_v2_logmessageperiod, tvb, PTP_V2_LOGMESSAGEPERIOD_OFFSET, 1, ENC_BIG_ENDIAN, &logmsgperiod);

        /* 127 is special */
        if (ptp_analyze_messages && logmsgperiod != 127) {
            proto_item_append_text(ti, " (%.6f s)", pow(2.0, (double)logmsgperiod));
        }

        switch(ptp_v2_messageid){
            case PTP_V2_ANNOUNCE_MESSAGE:{
                uint16_t    Offset;
                uint16_t    tlv_type;
                uint16_t    tlv_length;
                uint16_t    tlv_total_length;
                proto_tree *ptp_tlv_tree;
                proto_tree *ptp_tlv_wr_flags_tree;

                /* In 802.1AS there is no origin timestamp in an Announce Message */
                if(!is_802_1as){

                    proto_tree_add_item(ptp_tree, hf_ptp_v2_an_origintimestamp_seconds, tvb,
                        PTP_V2_AN_ORIGINTIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN);

                    proto_tree_add_item(ptp_tree, hf_ptp_v2_an_origintimestamp_nanoseconds, tvb,
                        PTP_V2_AN_ORIGINTIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                }

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_origincurrentutcoffset, tvb,
                    PTP_V2_AN_ORIGINCURRENTUTCOFFSET_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_priority1, tvb,
                    PTP_V2_AN_PRIORITY_1_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_grandmasterclockclass, tvb,
                    PTP_V2_AN_GRANDMASTERCLOCKCLASS_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_grandmasterclockaccuracy, tvb,
                    PTP_V2_AN_GRANDMASTERCLOCKACCURACY_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_grandmasterclockvariance, tvb,
                    PTP_V2_AN_GRANDMASTERCLOCKVARIANCE_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_priority2, tvb,
                    PTP_V2_AN_PRIORITY_2_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_grandmasterclockidentity, tvb,
                    PTP_V2_AN_GRANDMASTERCLOCKIDENTITY_OFFSET, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_an_localstepsremoved, tvb,
                        PTP_V2_AN_LOCALSTEPSREMOVED_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree,
                    hf_ptp_v2_an_timesource, tvb, PTP_V2_AN_TIMESOURCE_OFFSET, 1, ENC_BIG_ENDIAN);

                if (msg_len > 64)
                {
                    tlv_total_length = 0;
                    /* XXX It seems like at least 4 bytes must reamain to have a tlv_type and tlv_length */
                    while (tvb_reported_length_remaining(tvb, PTP_V2_AN_TLV_OFFSET + tlv_total_length) >= 4)
                    {
                        /* There are TLV's to be processed */
                        tlv_type = tvb_get_ntohs (tvb, PTP_V2_AN_TLV_OFFSET+tlv_total_length+PTP_V2_AN_TLV_TYPE_OFFSET);
                        tlv_length = tvb_get_ntohs (tvb, PTP_V2_AN_TLV_OFFSET+tlv_total_length+PTP_V2_AN_TLV_LENGTHFIELD_OFFSET);

                        ptp_tlv_tree = proto_tree_add_subtree_format(
                            ptp_tree,
                            tvb,
                            PTP_V2_AN_TLV_OFFSET + tlv_total_length,
                            tlv_length + PTP_V2_AN_TLV_DATA_OFFSET,
                            ett_ptp_v2_tlv, NULL, "%s TLV",
                            val_to_str_ext(tlv_type,
                                           &ptp_v2_TLV_type_vals_ext,
                                           "Unknown (%u)"));

                        proto_tree_add_item(ptp_tlv_tree,
                                            hf_ptp_v2_an_tlv_tlvtype,
                                            tvb,
                                            PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_TYPE_OFFSET,
                                            2,
                                            ENC_BIG_ENDIAN);

                        proto_tree_add_item(ptp_tlv_tree,
                                            hf_ptp_v2_an_tlv_lengthfield,
                                            tvb,
                                            PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_LENGTHFIELD_OFFSET,
                                            2,
                                            ENC_BIG_ENDIAN);

                        switch (tlv_type)
                        {
                            case PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION:
                            {
                                uint32_t org_id;
                                uint32_t subtype;

                                proto_tree_add_item(ptp_tlv_tree,
                                                    hf_ptp_v2_oe_tlv_organizationid,
                                                    tvb,
                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONID_OFFSET,
                                                    3,
                                                    ENC_BIG_ENDIAN);

                                org_id = tvb_get_ntoh24(tvb, PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONID_OFFSET);
                                subtype = tvb_get_ntoh24(tvb, PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET);

                                switch (org_id)
                                {
                                    case OUI_IEEE_C37_238:
                                    {

                                        switch (subtype)
                                        {
                                            case PTP_V2_OE_ORG_IEEE_C37_238_SUBTYPE_C37238TLV:
                                            {
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_organizationsubtype,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET,
                                                                    3,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c37238tlv_grandmasterid,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC37238TLV_GMID_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c37238tlv_grandmastertimeinaccuracy,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC37238TLV_GMINACCURACY_OFFSET,
                                                                    4,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c37238tlv_networktimeinaccuracy,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC37238TLV_NWINACCURACY_OFFSET,
                                                                    4,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c37238tlv_reserved,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC37238TLV_RESERVED_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                break;
                                            }
                                            case PTP_V2_OE_ORG_IEEE_C37_238_SUBTYPE_C372382017TLV:
                                            {
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_2017_organizationsubtype,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET,
                                                                    3,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c37238tlv_grandmasterid,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC37238TLV_GMID_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c372382017tlv_reserved,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC372382017TLV_RESERVED_OFFSET,
                                                                    4,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c37238tlv_totaltimeinaccuracy,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC37238TLV_TOTALINACCURACY_OFFSET,
                                                                    4,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_subtype_c37238tlv_reserved,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_IEEEC37238TLV_RESERVED_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                break;
                                            }



                                            default:
                                            {
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_organizationsubtype,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET,
                                                                    3,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_datafield,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_DATAFIELD_OFFSET,
                                                                    tlv_length - 6,
                                                                    ENC_NA);
                                                break;
                                            }
                                        }
                                        break;
                                    }
                                    case OUI_CERN:
                                    {
                                        proto_tree_add_item(ptp_tlv_tree,
                                                            hf_ptp_v2_an_tlv_oe_cern_subtype,
                                                            tvb,
                                                            PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET,
                                                            3,
                                                            ENC_BIG_ENDIAN);
                                        switch (subtype)
                                        {
                                            case PTP_V2_OE_ORG_CERN_SUBTYPE_WR_TLV:
                                            {
                                                proto_item *wrFlags_ti;
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_an_tlv_oe_cern_wrMessageID,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_WRTLV_MESSAGEID_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                wrFlags_ti = proto_tree_add_item(ptp_tlv_tree,
                                                                                 hf_ptp_v2_an_tlv_oe_cern_wrFlags,
                                                                                 tvb,
                                                                                 PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_WRTLV_FLAGS_OFFSET,
                                                                                 2,
                                                                                 ENC_BIG_ENDIAN);

                                                ptp_tlv_wr_flags_tree = proto_item_add_subtree(wrFlags_ti, ett_ptp_oe_wr_flags);

                                                proto_tree_add_item(ptp_tlv_wr_flags_tree,
                                                                    hf_ptp_v2_an_tlv_oe_cern_wrFlags_wrModeOn,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_WRTLV_FLAGS_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);

                                                proto_tree_add_item(ptp_tlv_wr_flags_tree,
                                                                    hf_ptp_v2_an_tlv_oe_cern_wrFlags_calibrated,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_WRTLV_FLAGS_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);

                                                proto_tree_add_item(ptp_tlv_wr_flags_tree,
                                                                    hf_ptp_v2_an_tlv_oe_cern_wrFlags_wrConfig,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_WRTLV_FLAGS_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                break;
                                            }
                                            default:
                                            {
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_datafield,
                                                                    tvb,
                                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_DATAFIELD_OFFSET,
                                                                    tlv_length - 6,
                                                                    ENC_NA);
                                                break;
                                            }
                                        }
                                        break;


                                    }
                                    default:
                                    {
                                        proto_tree_add_item(ptp_tlv_tree,
                                                            hf_ptp_v2_oe_tlv_organizationsubtype,
                                                            tvb,
                                                            PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET,
                                                            3,
                                                            ENC_BIG_ENDIAN);

                                        proto_tree_add_item(ptp_tlv_tree,
                                                            hf_ptp_v2_oe_tlv_datafield,
                                                            tvb,
                                                            PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_OE_DATAFIELD_OFFSET,
                                                            tlv_length - 6,
                                                            ENC_NA);
                                        break;
                                    }
                                }
                                break;
                            }
                            case PTP_V2_TLV_TYPE_ALTERNATE_TIME_OFFSET_INDICATOR:
                            {
                                proto_tree_add_item(ptp_tlv_tree,
                                                    hf_ptp_v2_atoi_tlv_keyfield,
                                                    tvb,
                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_ATOI_KEYFIELD_OFFSET,
                                                    1,
                                                    ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_tlv_tree,
                                                    hf_ptp_v2_atoi_tlv_currentoffset,
                                                    tvb,
                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_ATOI_CURRENTOFFSET_OFFSET,
                                                    4,
                                                    ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_tlv_tree,
                                                    hf_ptp_v2_atoi_tlv_jumpseconds,
                                                    tvb,
                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_ATOI_JUMPSECONDS_OFFSET,
                                                    4,
                                                    ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_tlv_tree,
                                                    hf_ptp_v2_atoi_tlv_timeofnextjump,
                                                    tvb,
                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_ATOI_TIMEOFNEXTJUMP_OFFSET,
                                                    6,
                                                    ENC_NA);

                                Offset = PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_ATOI_DISPLAYNAME_OFFSET;
                                dissect_ptp_v2_text(tvb,
                                                    &Offset,
                                                    ptp_tlv_tree,
                                                    hf_ptp_v2_atoi_tlv_displayname,
                                                    hf_ptp_v2_atoi_tlv_displayname_length);

                                break;
                            }
                            case PTP_V2_TLV_TYPE_PATH_TRACE:
                            {
                                uint16_t path_seq_total_length;

                                for(path_seq_total_length = 0; path_seq_total_length < tlv_length; path_seq_total_length+=8)
                                {
                                    proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_an_tlv_pathsequence, tvb,
                                                        PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_AS_AN_TLV_PATH_TRACE_OFFSET + path_seq_total_length,
                                                        8, ENC_BIG_ENDIAN);
                                }

                                break;
                            }
                            default:
                            {
                                proto_tree_add_item(ptp_tlv_tree,
                                                    hf_ptp_v2_an_tlv_data,
                                                    tvb,
                                                    PTP_V2_AN_TLV_OFFSET + tlv_total_length + PTP_V2_AN_TLV_DATA_OFFSET,
                                                    tlv_length,
                                                    ENC_NA);
                                break;
                            }
                        }

                        tlv_total_length += (tlv_length + PTP_V2_AN_TLV_DATA_OFFSET);
                    }
                }

                break;
            }

            case PTP_V2_SYNC_MESSAGE:
                if (is_802_1as && ((ptp_v2_flags & PTP_V2_FLAGS_TWO_STEP_BITMASK) == PTP_V2_FLAGS_TWO_STEP_BITMASK)) {
                    /* IEEE 802.1AS 2-step does not have Origin Timestamp in Sync! See 11.4.3 */
                    proto_tree_add_item(ptp_tree, hf_ptp_v2_sync_reserved, tvb,
                        PTP_V2_SDR_ORIGINTIMESTAMPSECONDS_OFFSET, 10, ENC_NA);
                } else {
                    /* regular PTP or 802.1AS 1-step */
                    proto_tree_add_item(ptp_tree, hf_ptp_v2_sdr_origintimestamp_seconds, tvb,
                        PTP_V2_SDR_ORIGINTIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN);

                    proto_tree_add_item(ptp_tree, hf_ptp_v2_sdr_origintimestamp_nanoseconds, tvb,
                        PTP_V2_SDR_ORIGINTIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                }

                if (is_802_1as && ((ptp_v2_flags & PTP_V2_FLAGS_TWO_STEP_BITMASK) != PTP_V2_FLAGS_TWO_STEP_BITMASK)) {
                    /* IEEE 802.1AS-2020 11.4.3 */
                    if (msg_len >= 76) {
                        dissect_follow_up_tlv(tvb, ptp_tree);
                    } else {
                        expert_add_info(pinfo, ti_root, &ei_ptp_v2_sync_no_fup_tlv);
                    }
                }

                if (ptp_analyze_messages) {
                    if (PTP_FRAME_INFO_SYNC_COMPLETE(frame_info)) {
                        if (frame_info->sync.syncInterval_valid) {
                            ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_sync_period, tvb, 0, 0, frame_info->sync.syncInterval);
                            proto_item_append_text(ti, " %s", "s");
                            proto_item_set_generated(ti);
                        }

                        if ((ptp_v2_flags & PTP_V2_FLAGS_TWO_STEP_BITMASK) == PTP_V2_FLAGS_TWO_STEP_BITMASK) {
                            ti = proto_tree_add_uint(ptp_tree, hf_ptp_v2_analysis_sync_to_followup, tvb, 0, 0, frame_info->sync.fup_frame_num);
                            proto_item_set_generated(ti);
                        } else {
                            if (frame_info->sync.calculated_timestamp_valid) {
                                ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_sync_timestamp, tvb, 0, 0, nstime_to_sec(&(frame_info->sync.calculated_timestamp)));
                                proto_item_set_generated(ti);
                                proto_tree *ts_tree = proto_item_add_subtree(ti, ett_ptp_analysis_timestamp);
                                ti = proto_tree_add_uint64(ts_tree, hf_ptp_v2_analysis_sync_timestamp_seconds, tvb, 0, 0, frame_info->sync.calculated_timestamp.secs);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_uint(ts_tree, hf_ptp_v2_analysis_sync_timestamp_nanoseconds, tvb, 0, 0, frame_info->sync.calculated_timestamp.nsecs);
                                proto_item_set_generated(ti);
                            }

                            if (frame_info->sync.syncRateRatio_valid) {
                                ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_sync_rateRatio, tvb, 0, 0, frame_info->sync.syncRateRatio);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_int(ptp_tree, hf_ptp_v2_analysis_sync_rateRatio_ppm, tvb, 0, 0, frame_info->sync.syncRateRatio_ppm);
                                proto_item_set_generated(ti);
                            }
                        }
                    } else if ((ptp_v2_flags & PTP_V2_FLAGS_TWO_STEP_BITMASK) == PTP_V2_FLAGS_TWO_STEP_BITMASK) {
                        /* No FollowUp found! */
                        expert_add_info(pinfo, ti_root, &ei_ptp_v2_sync_no_followup);
                    }
                }

                break;

            case PTP_V2_DELAY_REQ_MESSAGE:{
                proto_tree_add_item(ptp_tree, hf_ptp_v2_sdr_origintimestamp_seconds, tvb,
                    PTP_V2_SDR_ORIGINTIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_sdr_origintimestamp_nanoseconds, tvb,
                    PTP_V2_SDR_ORIGINTIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                break;
            }

            case PTP_V2_FOLLOWUP_MESSAGE:{
                proto_item *ti_tstamp;
                uint64_t    ts_sec;
                uint32_t    ts_ns;

                proto_tree_add_item_ret_uint64(ptp_tree, hf_ptp_v2_fu_preciseorigintimestamp_seconds, tvb,
                    PTP_V2_FU_PRECISEORIGINTIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN, &ts_sec);

                proto_tree_add_item_ret_uint(ptp_tree, hf_ptp_v2_fu_preciseorigintimestamp_nanoseconds, tvb,
                    PTP_V2_FU_PRECISEORIGINTIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN, &ts_ns);

                ti_tstamp = proto_tree_add_bytes_format_value(ptp_tree,
                                                              hf_ptp_v2_fu_preciseorigintimestamp_32bit,
                                                              tvb,
                                                              PTP_V2_FU_PRECISEORIGINTIMESTAMP_OFFSET,
                                                              10,
                                                              NULL,
                                                              "%"PRIu64, (ts_sec * NS_PER_S + ts_ns) % UINT64_C(0x100000000));

                proto_item_set_hidden(ti_tstamp);
                proto_item_set_generated(ti_tstamp);

                /* In 802.1AS there is a Follow_UP information TLV in the Follow Up Message */
                if(is_802_1as){
                    dissect_follow_up_tlv(tvb, ptp_tree);
                }

                if (ptp_analyze_messages) {
                    if (frame_info != NULL) {
                        if (PTP_FRAME_INFO_SYNC_COMPLETE(frame_info) && frame_info->sync.sync_two_step) {
                            if (frame_info->sync.calculated_timestamp_valid) {
                                ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_sync_timestamp, tvb, 0, 0, nstime_to_sec(&(frame_info->sync.calculated_timestamp)));
                                proto_item_set_generated(ti);
                                proto_tree *ts_tree = proto_item_add_subtree(ti, ett_ptp_analysis_timestamp);
                                ti = proto_tree_add_uint64(ts_tree, hf_ptp_v2_analysis_sync_timestamp_seconds, tvb, 0, 0, frame_info->sync.calculated_timestamp.secs);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_uint(ts_tree, hf_ptp_v2_analysis_sync_timestamp_nanoseconds, tvb, 0, 0, frame_info->sync.calculated_timestamp.nsecs);
                                proto_item_set_generated(ti);
                            }

                            if (frame_info->sync.syncRateRatio_valid) {
                                ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_sync_rateRatio, tvb, 0, 0, frame_info->sync.syncRateRatio);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_int(ptp_tree, hf_ptp_v2_analysis_sync_rateRatio_ppm, tvb, 0, 0, frame_info->sync.syncRateRatio_ppm);
                                proto_item_set_generated(ti);
                            }

                            ti = proto_tree_add_uint(ptp_tree, hf_ptp_v2_analysis_followup_to_sync, tvb, 0, 0, frame_info->sync.sync_frame_num);
                            proto_item_set_generated(ti);
                        } else {
                            /* No 2-step Sync found! */
                            expert_add_info(pinfo, ti_root, &ei_ptp_v2_followup_no_sync);
                        }
                    }
                }

                break;
            }

            case PTP_V2_DELAY_RESP_MESSAGE:{

                proto_tree_add_item(ptp_tree, hf_ptp_v2_dr_receivetimestamp_seconds, tvb,
                    PTP_V2_DR_RECEIVETIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_dr_receivetimestamp_nanoseconds, tvb,
                    PTP_V2_DR_RECEIVETIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_dr_requestingportidentity, tvb,
                    PTP_V2_DR_REQUESTINGPORTIDENTITY_OFFSET, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_dr_requestingsourceportid, tvb,
                    PTP_V2_DR_REQUESTINGSOURCEPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                break;
            }

            case PTP_V2_PEER_DELAY_REQ_MESSAGE:{
                /* In 802.1AS there is no origin timestamp in a Pdelay_Req Message */
                if(!is_802_1as){

                    proto_tree_add_item(ptp_tree, hf_ptp_v2_pdrq_origintimestamp_seconds, tvb,
                        PTP_V2_PDRQ_ORIGINTIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN);

                    proto_tree_add_item(ptp_tree, hf_ptp_v2_pdrq_origintimestamp_nanoseconds, tvb,
                        PTP_V2_PDRQ_ORIGINTIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);
                }

                if (ptp_analyze_messages) {
                    if (frame_info != NULL) {
                        if PTP_FRAME_INFO_PDELAY_REQ_SEEN(frame_info) {
                            if (frame_info->pdelay.pdelayInterval_valid) {
                                ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_pdelay_period, tvb, 0, 0, frame_info->pdelay.pdelayInterval);
                                proto_item_append_text(ti, " %s", "s");
                                proto_item_set_generated(ti);
                            }
                        }

                        if (frame_info->pdelay.pdelay_res_frame_num != 0) {
                            ti = proto_tree_add_uint(ptp_tree, hf_ptp_v2_analysis_pdelayreq_to_pdelayres, tvb, 0, 0, frame_info->pdelay.pdelay_res_frame_num);
                            proto_item_set_generated(ti);
                        } else {
                            /* No Response found! */
                            expert_add_info(pinfo, ti_root, &ei_ptp_v2_pdreq_no_pdresp);
                        }
                    }
                }
                break;
            }

            case PTP_V2_PEER_DELAY_RESP_MESSAGE:{

                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdrs_requestreceipttimestamp_seconds, tvb,
                    PTP_V2_PDRS_REQUESTRECEIPTTIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdrs_requestreceipttimestamp_nanoseconds, tvb,
                    PTP_V2_PDRS_REQUESTRECEIPTTIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdrs_requestingportidentity, tvb,
                    PTP_V2_PDRS_REQUESTINGPORTIDENTITY_OFFSET, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdrs_requestingsourceportid, tvb,
                    PTP_V2_PDRS_REQUESTINGSOURCEPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                if (ptp_analyze_messages) {
                    if (frame_info != NULL) {
                        if (frame_info->pdelay.pdelay_req_frame_num != 0) {
                            ti = proto_tree_add_uint(ptp_tree, hf_ptp_v2_analysis_pdelayres_to_pdelayreq, tvb, 0, 0, frame_info->pdelay.pdelay_req_frame_num);
                            proto_item_set_generated(ti);
                        } else {
                            /* No Request found! */
                            expert_add_info(pinfo, ti_root, &ei_ptp_v2_pdresp_no_pdreq);
                        }
                        if (frame_info->pdelay.pdelay_fup_frame_num != 0) {
                            ti = proto_tree_add_uint(ptp_tree, hf_ptp_v2_analysis_pdelayres_to_pdelayfup, tvb, 0, 0, frame_info->pdelay.pdelay_fup_frame_num);
                            proto_item_set_generated(ti);
                        } else {
                            /* No Follow Up found! */
                            expert_add_info(pinfo, ti_root, &ei_ptp_v2_pdresp_no_pdfup);
                        }
                        if (PTP_FRAME_INFO_PDELAY_COMPLETE(frame_info) && frame_info->pdelay.pdelay_res_two_step == false) {
                            /* Two step false but follow up received! */
                            /* According to 802.1AS-2011/2022 2-step must be true on pDelay Req */
                            expert_add_info(pinfo, ti_root, &ei_ptp_v2_pdresp_twostep);
                        }
                    }
                }
                break;
            }

            case PTP_V2_PEER_DELAY_FOLLOWUP_MESSAGE:{

                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdfu_responseorigintimestamp_seconds, tvb,
                    PTP_V2_PDFU_RESPONSEORIGINTIMESTAMPSECONDS_OFFSET, 6, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdfu_responseorigintimestamp_nanoseconds, tvb,
                    PTP_V2_PDFU_RESPONSEORIGINTIMESTAMPNANOSECONDS_OFFSET, 4, ENC_BIG_ENDIAN);


                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdfu_requestingportidentity, tvb,
                    PTP_V2_PDFU_REQUESTINGPORTIDENTITY_OFFSET, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_pdfu_requestingsourceportid, tvb,
                    PTP_V2_PDFU_REQUESTINGSOURCEPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                if (ptp_analyze_messages) {
                    if (frame_info != NULL) {
                        if PTP_FRAME_INFO_PDELAY_COMPLETE(frame_info) {
                            ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_pdelay_mpd_unscaled, tvb, 0, 0, nstime_to_sec(&frame_info->pdelay.mean_propagation_delay_unscaled));
                            proto_item_set_generated(ti);
                            proto_tree *ts_tree = proto_item_add_subtree(ti, ett_ptp_analysis_mean_propagation_delay);
                            ti = proto_tree_add_int64(ts_tree, hf_ptp_v2_analysis_pdelay_mpd_unscaled_seconds, tvb, 0, 0, frame_info->pdelay.mean_propagation_delay_unscaled.secs);
                            proto_item_set_generated(ti);
                            ti = proto_tree_add_int(ts_tree, hf_ptp_v2_analysis_pdelay_mpd_unscaled_nanoseconds, tvb, 0, 0, frame_info->pdelay.mean_propagation_delay_unscaled.nsecs);
                            proto_item_set_generated(ti);

                            if (frame_info->pdelay.neighborRateRatio_valid) {
                                ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_pdelay_mpd_scaled, tvb, 0, 0, frame_info->pdelay.mean_propagation_delay_scaled);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_double(ptp_tree, hf_ptp_v2_analysis_pdelay_neighRateRatio, tvb, 0, 0, frame_info->pdelay.neighborRateRatio);
                                proto_item_set_generated(ti);
                                ti = proto_tree_add_int(ptp_tree, hf_ptp_v2_analysis_pdelay_neighRateRatio_ppm, tvb, 0, 0, frame_info->pdelay.neighborRateRatio_ppm);
                                proto_item_set_generated(ti);
                            }
                        }

                        if (frame_info->pdelay.pdelay_res_frame_num != 0) {
                            ti = proto_tree_add_uint(ptp_tree, hf_ptp_v2_analysis_pdelayfup_to_pdelayres, tvb, 0, 0, frame_info->pdelay.pdelay_res_frame_num);
                            proto_item_set_generated(ti);
                        } else {
                            /* No Response found! */
                            expert_add_info(pinfo, ti_root, &ei_ptp_v2_pdfup_no_pdresp);
                        }
                    }
                }
                break;
            }

            case PTP_V2_SIGNALLING_MESSAGE:{
                uint16_t tlv_length;
                uint16_t tlv_type;
                proto_item *tlv_ti, *sig_tlv_flags_ti;
                proto_tree *ptp_tlv_tree, *sig_tlv_flags_tree;

                proto_tree_add_item(ptp_tree, hf_ptp_v2_sig_targetportidentity, tvb,
                    PTP_V2_SIG_TARGETPORTIDENTITY_OFFSET, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_sig_targetportid, tvb,
                    PTP_V2_SIG_TARGETPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                /* In 802.1AS there is a Message Interval Request TLV in the Signalling Message */
                if(is_802_1as){

                    /* There are TLV's to be processed */
                    tlv_length = tvb_get_ntohs (tvb, PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_LENGTHFIELD_OFFSET);
                    tlv_type = tvb_get_ntohs(tvb, PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_V2_SIG_TLV_TYPE_OFFSET);

                    switch (tlv_type)
                    {
                        case PTP_AS_SIG_TLV_TYPE_MESSAGEINTERVALREQUEST:{

                            ptp_tlv_tree = proto_tree_add_subtree(
                                ptp_tree,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET,
                                tlv_length + PTP_AS_SIG_TLV_ORGANIZATIONID_OFFSET,
                                ett_ptp_v2_tlv, NULL, "Message Interval Request TLV");

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_tlvtype,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_TYPE_OFFSET,
                                2,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_lengthfield,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_LENGTHFIELD_OFFSET,
                                2,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_organization_id,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_ORGANIZATIONID_OFFSET,
                                3,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_organization_subtype,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET,
                                3,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_link_delay_interval,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_LINKDELAYINTERVAL_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_time_sync_interval,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_TIMESYNCINTERVAL_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_announce_interval,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_ANNOUNCEINTERVAL_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);

                            sig_tlv_flags_ti = proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_flags,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_FLAGS_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);

                            sig_tlv_flags_tree = proto_item_add_subtree(sig_tlv_flags_ti, ett_ptp_as_sig_tlv_flags);

                            proto_tree_add_item(sig_tlv_flags_tree,
                                hf_ptp_as_sig_tlv_flags_comp_rate_ratio,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_FLAGS_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(sig_tlv_flags_tree,
                                hf_ptp_as_sig_tlv_flags_comp_mean_link_delay,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_FLAGS_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(sig_tlv_flags_tree,
                                hf_ptp_as_sig_tlv_flags_one_step_receive_capable,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_MESSAGEINTERVALREQ_FLAGS_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);
                            break;
                        }

                        case PTP_AS_SIG_TLV_TYPE_GPTPCAPABLE:{

                            uint16_t organization_subtype;

                            organization_subtype = tvb_get_ntohs(tvb, PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET);

                            if (organization_subtype == PTP_AS_SIG_TLV_TYPE_GPTPCAPABLE_MESSSAGEINTERVAL_ORG_SUB_TYPE){
                                ptp_tlv_tree = proto_tree_add_subtree(
                                    ptp_tree,
                                    tvb,
                                    PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET,
                                    tlv_length + PTP_AS_SIG_TLV_ORGANIZATIONID_OFFSET,
                                    ett_ptp_v2_tlv, NULL, "gPTP-capable message interval request TLV");
                            }
                            else{

                                ptp_tlv_tree = proto_tree_add_subtree(
                                    ptp_tree,
                                    tvb,
                                    PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET,
                                    tlv_length + PTP_AS_SIG_TLV_ORGANIZATIONID_OFFSET,
                                    ett_ptp_v2_tlv, NULL, "gPTP-capable TLV");
                            }

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_tlvtype,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_TYPE_OFFSET,
                                2,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_lengthfield,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_LENGTHFIELD_OFFSET,
                                2,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_organization_id,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_ORGANIZATIONID_OFFSET,
                                3,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_organization_subtype,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET,
                                3,
                                ENC_BIG_ENDIAN);

                            proto_tree_add_item(ptp_tlv_tree,
                                hf_ptp_as_sig_tlv_gptp_capable_message_interval,
                                tvb,
                                PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_GPTPCAPABLE_MESSAGEINTERVAL_OFFSET,
                                1,
                                ENC_BIG_ENDIAN);

                            if (organization_subtype == PTP_AS_SIG_TLV_TYPE_GPTPCAPABLE_ORG_SUB_TYPE){
                                proto_tree_add_item(ptp_tlv_tree,
                                    hf_ptp_as_sig_tlv_flags,
                                    tvb,
                                    PTP_AS_SIG_TLV_MESSAGEINTERVALREQUEST_OFFSET + PTP_AS_SIG_TLV_GPTPCAPABLE_FLAGS_OFFSET,
                                    1,
                                    ENC_BIG_ENDIAN);
                            }
                            break;
                        }
                    }

                } else {
                    unsigned   proto_len;
                    uint32_t tlv_offset;
                    int8_t  log_inter_message_period;
                    double period = 0.0f;
                    double rate   = 0.0f;

                    proto_item *ptp_tlv_period;
                    proto_tree *ptp_tlv_period_tree;

                    proto_len  = tvb_reported_length(tvb);
                    tlv_offset = PTP_V2_SIG_TLV_START;

                    while (tlv_offset < proto_len) {

                        /* 14.1.1 tlvType */
                        tlv_type     = tvb_get_ntohs(tvb, tlv_offset + PTP_V2_SIG_TLV_TYPE_OFFSET);
                        tlv_ti       = proto_tree_add_item(ptp_tree, hf_ptp_v2_sig_tlv_tlvType, tvb,
                                                           tlv_offset + PTP_V2_SIG_TLV_TYPE_OFFSET, PTP_V2_SIG_TLV_TYPE_LEN, ENC_BIG_ENDIAN);

                        ptp_tlv_tree = proto_item_add_subtree(tlv_ti, ett_ptp_v2_tlv);

                        /* 14.1.2 lengthField */
                        tlv_length   = tvb_get_ntohs(tvb, tlv_offset + PTP_V2_SIG_TLV_LENGTH_OFFSET);
                        proto_tree_add_uint(ptp_tlv_tree, hf_ptp_v2_sig_tlv_lengthField, tvb,
                                            tlv_offset + PTP_V2_SIG_TLV_LENGTH_OFFSET, PTP_V2_SIG_TLV_LENGTH_LEN, tlv_length);

                        switch (tlv_type) {

                            /* Request Unicast Transmission */
                            case PTP_V2_TLV_TYPE_REQUEST_UNICAST_TRANSMISSION:

                                /* 16.1.4.1.3 messageType */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_messageType, tvb,
                                                    tlv_offset + PTP_V2_SIG_TLV_MESSAGE_TYPE_OFFSET, PTP_V2_SIG_TLV_MESSAGE_TYPE_LEN, ENC_BIG_ENDIAN);

                                /* 16.1.4.1.4 logInterMessagePeriod */
                                log_inter_message_period = tvb_get_uint8(tvb, tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET);
                                period = pow(2, log_inter_message_period);

                                ptp_tlv_period = proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_logInterMessagePeriod, tvb,
                                                                     tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET, PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN, ENC_BIG_ENDIAN);

                                ptp_tlv_period_tree = proto_item_add_subtree(ptp_tlv_period, ett_ptp_v2_tlv_log_period);

                                proto_tree_add_int_format_value(ptp_tlv_period_tree, hf_ptp_v2_sig_tlv_logInterMessagePeriod_period, tvb,
                                                                tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET, PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN, log_inter_message_period, "every %lg seconds", period);

                                if (period > 0) {
                                    rate = 1 / period;
                                    proto_tree_add_int_format_value(ptp_tlv_period_tree, hf_ptp_v2_sig_tlv_logInterMessagePeriod_rate, tvb,
                                                                tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET, PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN, log_inter_message_period, "%lg packets/sec", rate);
                                } else {
                                    proto_tree_add_expert_format(ptp_tlv_period_tree, pinfo, &ei_ptp_v2_period_invalid,
                                        tvb, tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET,
                                        PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN,
                                        "Invalid InterMessagePeriod: %lg", period);
                                }

                                /* 16.1.4.1.5 durationField */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_durationField, tvb,
                                                                 tlv_offset + PTP_V2_SIG_TLV_DURATION_FIELD_OFFSET, PTP_V2_SIG_TLV_DURATION_FIELD_LEN, ENC_BIG_ENDIAN);

                                break;

                            /* Grant Unicast Transmission */
                            case PTP_V2_TLV_TYPE_GRANT_UNICAST_TRANSMISSION:

                                /* 16.1.4.2.3 messageType */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_messageType, tvb,
                                                    tlv_offset + PTP_V2_SIG_TLV_MESSAGE_TYPE_OFFSET, PTP_V2_SIG_TLV_MESSAGE_TYPE_LEN, ENC_BIG_ENDIAN);

                                /* 16.1.4.2.4 logInterMessagePeriod */
                                log_inter_message_period = tvb_get_uint8(tvb, tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET);
                                period = pow(2, log_inter_message_period);

                                ptp_tlv_period = proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_logInterMessagePeriod, tvb,
                                                                     tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET, PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN, ENC_BIG_ENDIAN);

                                ptp_tlv_period_tree = proto_item_add_subtree(ptp_tlv_period, ett_ptp_v2_tlv_log_period);

                                proto_tree_add_int_format_value(ptp_tlv_period_tree, hf_ptp_v2_sig_tlv_logInterMessagePeriod_period, tvb,
                                                                tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET, PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN, log_inter_message_period, "every %lg seconds", period);

                                if (period > 0) {
                                    rate = 1 / period;
                                    proto_tree_add_int_format_value(ptp_tlv_period_tree, hf_ptp_v2_sig_tlv_logInterMessagePeriod_rate, tvb,
                                                                tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET, PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN, log_inter_message_period, "%lg packets/sec", rate);
                                } else {
                                    proto_tree_add_expert_format(ptp_tlv_period_tree, pinfo, &ei_ptp_v2_period_invalid,
                                        tvb, tlv_offset + PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_OFFSET,
                                        PTP_V2_SIG_TLV_LOG_INTER_MESSAGE_PERIOD_LEN,
                                        "Invalid InterMessagePeriod: %lg", period);
                                }

                                /* 16.1.4.2.5 durationField */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_durationField, tvb,
                                                                 tlv_offset + PTP_V2_SIG_TLV_DURATION_FIELD_OFFSET, PTP_V2_SIG_TLV_DURATION_FIELD_LEN, ENC_BIG_ENDIAN);

                                /* 16.1.4.2.6 renewalInvited */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_renewalInvited, tvb,
                                                    tlv_offset + PTP_V2_SIG_TLV_RENEWAL_INVITED_OFFSET, PTP_V2_SIG_TLV_RENEWAL_INVITED_LEN, ENC_BIG_ENDIAN);

                                break;

                            /* Cancel Unicast Transmission */
                            case PTP_V2_TLV_TYPE_CANCEL_UNICAST_TRANSMISSION:

                                /* 16.1.4.3.3 messageType */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_messageType, tvb,
                                                    tlv_offset + PTP_V2_SIG_TLV_MESSAGE_TYPE_OFFSET, PTP_V2_SIG_TLV_MESSAGE_TYPE_LEN, ENC_BIG_ENDIAN);

                                break;

                            /* Acknowledge Cancel Unicast Transmission */
                            case PTP_V2_TLV_TYPE_ACKNOWLEDGE_CANCEL_UNICAST_TRANSMISSION:

                                /* 16.1.4.4.3 messageType */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_messageType, tvb,
                                                    tlv_offset + PTP_V2_SIG_TLV_MESSAGE_TYPE_OFFSET, PTP_V2_SIG_TLV_MESSAGE_TYPE_LEN, ENC_BIG_ENDIAN);

                                break;

                            case PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION:
                            {
                                uint32_t org_id;
                                uint32_t subtype;
                                uint16_t    tlv_total_length = tlv_offset;
                                proto_tree_add_item(ptp_tlv_tree,
                                                    hf_ptp_v2_oe_tlv_organizationid,
                                                    tvb,
                                                    tlv_total_length + PTP_V2_SIG_TLV_ORGANIZATIONID_OFFSET,
                                                    3,
                                                    ENC_BIG_ENDIAN);

                                org_id = tvb_get_ntoh24(tvb, tlv_total_length + PTP_V2_SIG_TLV_ORGANIZATIONID_OFFSET);
                                subtype = tvb_get_ntoh24(tvb, tlv_total_length + PTP_V2_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET);

                                switch (org_id)
                                {
                                    case OUI_CERN:
                                    {
                                        proto_tree_add_item(ptp_tlv_tree,
                                                            hf_ptp_v2_sig_oe_tlv_cern_subtype,
                                                            tvb,
                                                            tlv_total_length + PTP_V2_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET,
                                                            3,
                                                            ENC_BIG_ENDIAN);
                                        switch (subtype)
                                        {
                                            case PTP_V2_OE_ORG_CERN_SUBTYPE_WR_TLV:
                                            {
                                                uint16_t wr_messageId;
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_sig_oe_tlv_cern_wrMessageID,
                                                                    tvb,
                                                                    tlv_total_length + PTP_V2_SIG_TLV_WRTLV_MESSAGEID_OFFSET,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                wr_messageId = tvb_get_ntohs(tvb, tlv_total_length + PTP_V2_SIG_TLV_WRTLV_MESSAGEID_OFFSET);
                                                switch (wr_messageId)
                                                {
                                                    case PTP_V2_OE_ORG_CERN_WRMESSAGEID_CALIBRATE:
                                                        proto_tree_add_item(ptp_tlv_tree,
                                                                            hf_ptp_v2_sig_oe_tlv_cern_calSendPattern,
                                                                            tvb,
                                                                            tlv_total_length + PTP_V2_SIG_TLV_WRTLV_CALSENDPATTERN_OFFSET,
                                                                            1,
                                                                            ENC_BIG_ENDIAN);
                                                        proto_tree_add_item(ptp_tlv_tree,
                                                                            hf_ptp_v2_sig_oe_tlv_cern_calRety,
                                                                            tvb,
                                                                            tlv_total_length + PTP_V2_SIG_TLV_WRTLV_CALRETRY_OFFSET,
                                                                            1,
                                                                            ENC_BIG_ENDIAN);
                                                        proto_tree_add_item(ptp_tlv_tree,
                                                                            hf_ptp_v2_sig_oe_tlv_cern_calPeriod,
                                                                            tvb,
                                                                            tlv_total_length + PTP_V2_SIG_TLV_WRTLV_CALPERIOD_OFFSET,
                                                                            4,
                                                                            ENC_BIG_ENDIAN);

                                                        break;
                                                    case PTP_V2_OE_ORG_CERN_WRMESSAGEID_CALIBRATED:
                                                    {
                                                        uint64_t deltaTx;
                                                        uint64_t deltaRx;
                                                        deltaTx = tvb_get_ntoh64(tvb, tlv_total_length + PTP_V2_SIG_TLV_WRTLV_DELTATX_OFFSET);
                                                        deltaRx = tvb_get_ntoh64(tvb, tlv_total_length + PTP_V2_SIG_TLV_WRTLV_DELTARX_OFFSET);
                                                        proto_tree_add_bytes_format_value(ptp_tlv_tree,
                                                                                          hf_ptp_v2_sig_oe_tlv_cern_deltaTx,
                                                                                          tvb,
                                                                                          tlv_total_length + PTP_V2_SIG_TLV_WRTLV_DELTATX_OFFSET,
                                                                                          8,
                                                                                          NULL,
                                                                                          "%lf ps", (double) deltaTx/(1 << 16));
                                                        proto_tree_add_bytes_format_value(ptp_tlv_tree,
                                                                                          hf_ptp_v2_sig_oe_tlv_cern_deltaRx,
                                                                                          tvb,
                                                                                          tlv_total_length + PTP_V2_SIG_TLV_WRTLV_DELTARX_OFFSET,
                                                                                          8,
                                                                                          NULL,
                                                                                          "%lf ps", (double) deltaRx/(1 << 16));
                                                        break;
                                                    }
                                                    default:
                                                        break;
                                                }
                                                break;
                                            }
                                            default:
                                            {
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_datafield,
                                                                    tvb,
                                                                    tlv_total_length + PTP_V2_AN_TLV_OE_DATAFIELD_OFFSET,
                                                                    tlv_length - 6,
                                                                    ENC_NA);
                                                break;
                                            }
                                        }
                                        break;

                                    }
                                    case OUI_ITU_T:
                                    {
                                        proto_tree_add_item(ptp_tlv_tree,
                                                            hf_ptp_v2_sig_oe_tlv_itut_subtype,
                                                            tvb,
                                                            tlv_total_length + PTP_V2_SIG_TLV_ORGANIZATIONSUBTYPE_OFFSET,
                                                            3,
                                                            ENC_BIG_ENDIAN);
                                        switch (subtype)
                                        {
                                            case PTP_V2_INTERFACE_RATE_TLV:
                                            {
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_sig_tlv_interface_bit_period,
                                                                    tvb,
                                                                    tlv_total_length + PTP_SIG_TLV_INTERFACE_BIT_PERIOD,
                                                                    8,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_sig_tlv_numberbits_before_timestamp,
                                                                    tvb,
                                                                    tlv_total_length + PTP_SIG_TLV_NUMBERBITS_BEFORE_TIMESTAMP,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_sig_tlv_numberbits_after_timestamp,
                                                                    tvb,
                                                                    tlv_total_length + PTP_SIG_TLV_NUMBERBITS_AFTER_TIMESTAMP,
                                                                    2,
                                                                    ENC_BIG_ENDIAN);
                                                break;
                                            }
                                            default:
                                            {
                                                proto_tree_add_item(ptp_tlv_tree,
                                                                    hf_ptp_v2_oe_tlv_datafield,
                                                                    tvb,
                                                                    tlv_total_length + PTP_V2_AN_TLV_OE_DATAFIELD_OFFSET,
                                                                    tlv_length - 6,
                                                                    ENC_NA);
                                                break;
                                            }
                                        }
                                        break;
                                    }
                                    default:
                                    {
                                        proto_tree_add_item(ptp_tlv_tree,
                                                            hf_ptp_v2_oe_tlv_organizationsubtype,
                                                            tvb,
                                                            tlv_total_length + PTP_V2_AN_TLV_OE_ORGANIZATIONSUBTYPE_OFFSET,
                                                            3,
                                                            ENC_BIG_ENDIAN);
                                        break;
                                    }
                                }
                                break;
                            }

                            case PTP_V2_TLV_TYPE_L1_SYNC:
                            {
                                uint16_t l1sync_flags;
                                proto_item *l1Flags_ti;
                                proto_tree *ptp_tlv_l1sync_flags_tree;
                                /* In the basic format of the L1_SYNC flags field is 2 bytes */
                                uint8_t flags_len = PTP_V2_SIG_TLV_L1SYNC_FLAGS_BASIC_FORMAT;

                                /* Version with 2 bytes flags field */
                                static int * const data_mode_flags2[] = {
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_ope,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_cr,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_rcr,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_tcr,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_ic,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_irc,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_itc,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags2_reserved,
                                        NULL
                                };

                                /* Version with 3 bytes flags field */
                                static int * const data_mode_flags3[] = {
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_ope,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_cr,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_rcr,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_tcr,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_ic,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_irc,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_itc,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_fov,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_pov,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_tct,
                                        &hf_ptp_v2_sig_tlv_l1sync_flags3_reserved,
                                        NULL
                                };

                                /* Get the value of flags */
                                l1sync_flags = tvb_get_ntohs(tvb, tlv_offset + PTP_V2_SIG_TLV_L1SYNC_FLAGS_OFFSET);

                                /* Check if the frame has extended format of L1_SYNC flags field */
                                if (l1sync_flags & PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_OPE_BITMASK) {
                                        flags_len = PTP_V2_SIG_TLV_L1SYNC_FLAGS_EXT_FORMAT;
                                }

                                l1Flags_ti = proto_tree_add_item(ptp_tlv_tree,
                                                                 flags_len == PTP_V2_SIG_TLV_L1SYNC_FLAGS_BASIC_FORMAT ? hf_ptp_v2_sig_tlv_flags2 : hf_ptp_v2_sig_tlv_flags3,
                                                                 tvb,
                                                                 tlv_offset + PTP_V2_SIG_TLV_L1SYNC_FLAGS_OFFSET,
                                                                 flags_len,
                                                                 ENC_BIG_ENDIAN);

                                ptp_tlv_l1sync_flags_tree = proto_item_add_subtree(l1Flags_ti, ett_ptp_v2_sig_l1sync_flags);

                                /* Check if the frame has extended format */
                                if (!(l1sync_flags & PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_OPE_BITMASK)) {
                                        proto_tree_add_bitmask_list(ptp_tlv_l1sync_flags_tree,
                                                                    tvb,
                                                                    tlv_offset + PTP_V2_SIG_TLV_L1SYNC_FLAGS_OFFSET,
                                                                    flags_len,
                                                                    data_mode_flags2,
                                                                    ENC_BIG_ENDIAN);
                                } else {
                                        uint16_t value_offset;

                                        proto_tree_add_bitmask_list(ptp_tlv_l1sync_flags_tree,
                                                                    tvb,
                                                                    tlv_offset + PTP_V2_SIG_TLV_L1SYNC_FLAGS_OFFSET,
                                                                    flags_len,
                                                                    data_mode_flags3,
                                                                    ENC_BIG_ENDIAN);

                                        value_offset = tlv_offset + PTP_V2_SIG_TLV_L1SYNCEXT_PHASE_OFFSET_TX_OFFSET;
                                        dissect_ptp_v2_timeInterval(tvb,
                                                                    &value_offset,
                                                                    ptp_tlv_tree,
                                                                    "phaseOffsetTx",
                                                                    hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTx_ns,
                                                                    hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTx_subns);

                                        value_offset = tlv_offset + PTP_V2_SIG_TLV_L1SYNCEXT_PHASE_OFFSET_TX_TIMESTAMP_OFFSET;
                                        dissect_ptp_v2_timetstamp(tvb,
                                                                  &value_offset,
                                                                  ptp_tlv_tree,
                                                                  "phaseOffsetTxTimestamp",
                                                                  hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTxTimestamp_s,
                                                                  hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTxTimestamp_ns);

                                        value_offset = tlv_offset + PTP_V2_SIG_TLV_L1SYNCEXT_FREQ_OFFSET_TX_OFFSET;
                                        dissect_ptp_v2_timeInterval(tvb,
                                                                    &value_offset,
                                                                    ptp_tlv_tree,
                                                                    "freqOffsetTx",
                                                                    hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTx_ns,
                                                                    hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTx_subns);

                                        value_offset = tlv_offset + PTP_V2_SIG_TLV_L1SYNCEXT_FREQ_OFFSET_TX_TIMESTAMP_OFFSET;
                                        dissect_ptp_v2_timetstamp(tvb,
                                                                  &value_offset,
                                                                  ptp_tlv_tree,
                                                                  "freqOffsetTxTimestamp",
                                                                  hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTxTimestamp_s,
                                                                  hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTxTimestamp_ns);
                                }

                                break;
                            }

                            default:
                                /* TODO: Add dissector for other TLVs */
                                proto_tree_add_item(ptp_tlv_tree, hf_ptp_v2_sig_tlv_data, tvb,
                                                    tlv_offset + PTP_V2_SIG_TLV_VALUE_OFFSET, tlv_length, ENC_NA);
                        }

                        tlv_offset += PTP_V2_SIG_TLV_TYPE_LEN +
                                      PTP_V2_SIG_TLV_LENGTH_LEN +
                                      tlv_length;
                    }
                }
                break;
            }

            case PTP_V2_MANAGEMENT_MESSAGE:
            {
                uint16_t tlv_type, tlv_length;

                proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_targetportidentity, tvb,
                    PTP_V2_MM_TARGETPORTIDENTITY_OFFSET, 8, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_targetportid, tvb,
                    PTP_V2_MM_TARGETPORTID_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_startingboundaryhops, tvb,
                    PTP_V2_MM_STARTINGBOUNDARYHOPS_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_boundaryhops, tvb,
                    PTP_V2_MM_BOUNDARYHOPS_OFFSET, 1, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_action, tvb,
                    PTP_V2_MM_ACTION_OFFSET, 1, ENC_BIG_ENDIAN);

                /* management TLV */
                proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_tlvType, tvb,
                    PTP_V2_MM_TLV_TYPE_OFFSET, 2, ENC_BIG_ENDIAN);

                proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_lengthField, tvb,
                    PTP_V2_MM_TLV_LENGTHFIELD_OFFSET, 2, ENC_BIG_ENDIAN);

                tlv_type = tvb_get_ntohs (tvb, PTP_V2_MM_TLV_TYPE_OFFSET);
                tlv_length = tvb_get_ntohs (tvb, PTP_V2_MM_TLV_LENGTHFIELD_OFFSET);

                /* For management there are PTP_V2_TLV_TYPE_MANAGEMENT and PTP_V2_TLV_TYPE_MANAGEMENT_ERROR_STATUS TLVs */
                switch(tlv_type) {
                    case PTP_V2_TLV_TYPE_MANAGEMENT:
                    {
                        uint16_t ptp_v2_managementId;
                        uint16_t Offset = PTP_V2_MM_TLV_DATAFIELD_OFFSET;

                        proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_managementId, tvb,
                            PTP_V2_MM_TLV_MANAGEMENTID_OFFSET, 2, ENC_BIG_ENDIAN);

                        ptp_v2_managementId = tvb_get_ntohs (tvb, PTP_V2_MM_TLV_MANAGEMENTID_OFFSET);

                        if (tlv_length <= 2)
                        {
                            /* no data */
                            break;
                        }

                        managementData_ti = proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_data, tvb, Offset, tlv_length - 2, ENC_NA);

                        /* data field of the management message (subtree) */
                        ptp_managementData_tree = proto_item_add_subtree(managementData_ti, ett_ptp_v2_managementData);

                        switch(ptp_v2_managementId) {
                            case PTP_V2_MM_ID_NULL_MANAGEMENT:
                            {
                                /* no data in NULL management */
                                break;
                            }
                            case PTP_V2_MM_ID_CLOCK_DESCRIPTION:
                            {
                                uint16_t N = 0, S = 0;
                                clockType_ti = proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockType, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);

                                ptp_clockType_tree = proto_item_add_subtree(clockType_ti, ett_ptp_v2_clockType);
                                    /* ClockType Subtree */
                                    proto_tree_add_item(ptp_clockType_tree, hf_ptp_v2_mm_clockType_ordinaryClock, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(ptp_clockType_tree, hf_ptp_v2_mm_clockType_boundaryClock, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(ptp_clockType_tree, hf_ptp_v2_mm_clockType_p2p_transparentClock, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(ptp_clockType_tree, hf_ptp_v2_mm_clockType_e2e_transparentClock, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(ptp_clockType_tree, hf_ptp_v2_mm_clockType_managementNode, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(ptp_clockType_tree, hf_ptp_v2_mm_clockType_reserved, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                dissect_ptp_v2_text (tvb, &Offset, ptp_managementData_tree,
                                                     hf_ptp_v2_mm_physicalLayerProtocol, hf_ptp_v2_mm_physicalLayerProtocol_length);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_physicalAddressLength, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);

                                S = tvb_get_ntohs (tvb, Offset);
                                Offset +=2;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_physicalAddress, tvb,
                                    Offset, S, ENC_NA);
                                Offset += S;

                                N = tvb_get_ntohs (tvb, Offset+2);

                                protocolAddress_ti = proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_protocolAddress, tvb,
                                    Offset+4, N, ENC_NA);

                                ptp_protocolAddress_tree = proto_item_add_subtree(protocolAddress_ti, ett_ptp_v2_protocolAddress);
                                    /* physicalLayerProtocol subtree */
                                    proto_tree_add_item(ptp_protocolAddress_tree, hf_ptp_v2_mm_protocolAddress_networkProtocol, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(ptp_protocolAddress_tree, hf_ptp_v2_mm_protocolAddress_length, tvb,
                                        Offset+2, 2, ENC_BIG_ENDIAN);

                                    proto_tree_add_item(ptp_protocolAddress_tree, hf_ptp_v2_mm_protocolAddress, tvb,
                                        Offset+4, N, ENC_NA);
                                N = N + 4;
                                Offset += N;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_manufacturerIdentity, tvb,
                                    Offset, 3, ENC_NA);

                                Offset += 3;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);
                                Offset += 1;

                                dissect_ptp_v2_text (tvb, &Offset, ptp_managementData_tree,
                                                     hf_ptp_v2_mm_productDescription, hf_ptp_v2_mm_productDescription_length);
                                dissect_ptp_v2_text (tvb, &Offset, ptp_managementData_tree,
                                                     hf_ptp_v2_mm_revisionData, hf_ptp_v2_mm_revisionData_length);
                                dissect_ptp_v2_text (tvb, &Offset, ptp_managementData_tree,
                                                     hf_ptp_v2_mm_userDescription, hf_ptp_v2_mm_userDescription_length);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_profileIdentity, tvb,
                                    Offset, 6, ENC_NA);
                                Offset += 6;

                                /* Wenn Offset nicht gerade folgt noch ein pad Bit */
                                if ( (Offset - PTP_V2_MM_TLV_DATAFIELD_OFFSET) % 2 )
                                {
                                    proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_pad, tvb,
                                    Offset, 1, ENC_NA);
                                }
                                break;
                            }
                            case PTP_V2_MM_ID_USER_DESCRIPTION:
                            {

                                dissect_ptp_v2_text (tvb, &Offset, ptp_managementData_tree,
                                                     hf_ptp_v2_mm_userDescription, hf_ptp_v2_mm_userDescription_length);

                                /* Wenn Offset nicht gerade folgt noch ein pad Bit */
                                if ( (Offset - PTP_V2_MM_TLV_DATAFIELD_OFFSET) % 2 )
                                {
                                    proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_pad, tvb,
                                    Offset, 1, ENC_NA);
                                }
                                break;
                            }
                            case PTP_V2_MM_ID_SAVE_IN_NON_VOLATILE_STORAGE:
                            {
                                /* no data */
                                break;
                            }
                            case PTP_V2_MM_ID_RESET_NON_VOLATILE_STORAGE:
                            {
                                /* no data */
                                break;
                            }
                            case PTP_V2_MM_ID_INITIALIZE:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_initializationKey, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                break;
                            }
                            case PTP_V2_MM_ID_FAULT_LOG:
                            {
                                uint16_t ii, num = 0;
                                proto_tree  *ptpError_subtree;

                                num = tvb_get_ntohs (tvb, Offset);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_numberOfFaultRecords, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                for (ii = 0; ii < num; ii++)
                                {
                                    ptpError_subtree = proto_tree_add_subtree(ptp_managementData_tree, tvb, Offset, tvb_get_ntohs (tvb, Offset),
                                            ett_ptp_v2_faultRecord, NULL, "Fault record");

                                    proto_tree_add_item(ptpError_subtree, hf_ptp_v2_mm_faultRecordLength, tvb,
                                        Offset, 2, ENC_BIG_ENDIAN);
                                    Offset +=2;

                                    proto_tree_add_item(ptpError_subtree, hf_ptp_v2_mm_faultTime_s, tvb,
                                                Offset, 6, ENC_BIG_ENDIAN);

                                    Offset +=6;
                                    proto_tree_add_item(ptpError_subtree, hf_ptp_v2_mm_faultTime_ns, tvb,
                                                Offset, 4, ENC_BIG_ENDIAN);
                                    Offset +=4;
                                    proto_tree_add_item(ptpError_subtree, hf_ptp_v2_mm_severityCode, tvb,
                                                Offset, 1, ENC_BIG_ENDIAN);
                                    Offset +=1;

                                    dissect_ptp_v2_text (tvb, &Offset, ptpError_subtree,
                                                         hf_ptp_v2_mm_faultName, hf_ptp_v2_mm_faultName_length);

                                    dissect_ptp_v2_text (tvb, &Offset, ptpError_subtree,
                                                         hf_ptp_v2_mm_faultValue, hf_ptp_v2_mm_faultValue_length);

                                    dissect_ptp_v2_text (tvb, &Offset, ptpError_subtree,
                                                         hf_ptp_v2_mm_faultDescription, hf_ptp_v2_mm_faultDescription_length);
                                }

                                /* Wenn Offset nicht gerade folgt noch ein pad Bit */
                                if ( (Offset - PTP_V2_MM_TLV_DATAFIELD_OFFSET) % 2 )
                                {
                                    proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_pad, tvb,
                                        Offset, 1, ENC_NA);
                                }
                                break;
                            }
                            case PTP_V2_MM_ID_FAULT_LOG_RESET:
                            {
                                /* no data */
                                break;
                            }
                            case PTP_V2_MM_ID_DEFAULT_DATA_SET:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_TSC, tvb,
                                    PTP_V2_MM_TLV_DATAFIELD_OFFSET, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_dds_SO, tvb,
                                    PTP_V2_MM_TLV_DATAFIELD_OFFSET, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    PTP_V2_MM_RESERVED1, 1, ENC_NA);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_numberPorts, tvb,
                                    PTP_V2_MM_NUMBERPORTS, 2, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_priority1, tvb,
                                    PTP_V2_MM_PRIORITY1, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockclass, tvb,
                                    PTP_V2_MM_CLOCKQUALITY, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockaccuracy, tvb,
                                    PTP_V2_MM_CLOCKQUALITY+1, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockvariance, tvb,
                                    PTP_V2_MM_CLOCKQUALITY+2, 2, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_priority2, tvb,
                                    PTP_V2_MM_PRIORITY2, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockidentity, tvb,
                                    PTP_V2_MM_CLOCKIDENTITY, 8, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_domainNumber, tvb,
                                    PTP_V2_MM_DOMAINNUMBER, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    PTP_V2_MM_RESERVED2, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_CURRENT_DATA_SET:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_stepsRemoved, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                dissect_ptp_v2_timeInterval(tvb, &Offset, ptp_managementData_tree,
                                    "Offset from Master", hf_ptp_v2_mm_offset_ns, hf_ptp_v2_mm_offset_subns);
                                dissect_ptp_v2_timeInterval(tvb, &Offset, ptp_managementData_tree,
                                    "Mean path delay", hf_ptp_v2_mm_pathDelay_ns, hf_ptp_v2_mm_pathDelay_subns);
                                break;
                            }
                            case PTP_V2_MM_ID_PARENT_DATA_SET:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_parentIdentity, tvb,
                                    Offset, 8, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_parentPort, tvb,
                                    Offset+8, 2, ENC_BIG_ENDIAN);
                                Offset +=10;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_parentStats, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_observedParentOffsetScaledLogVariance, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_observedParentClockPhaseChangeRate, tvb,
                                    Offset, 4, ENC_BIG_ENDIAN);
                                Offset +=4;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_grandmasterPriority1, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_grandmasterclockclass, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_grandmasterclockaccuracy, tvb,
                                    Offset+1, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_grandmasterclockvariance, tvb,
                                    Offset+2, 2, ENC_BIG_ENDIAN);
                                Offset += 4;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_grandmasterPriority2, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_grandmasterIdentity, tvb,
                                    Offset, 8, ENC_BIG_ENDIAN);

                                break;
                            }
                            case PTP_V2_MM_ID_TIME_PROPERTIES_DATA_SET:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_currentUtcOffset, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_LI_61, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_LI_59, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_UTCV, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_PTP, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_TTRA, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_FTRA, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_timesource, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                break;
                            }
                            case PTP_V2_MM_ID_PORT_DATA_SET:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockidentity, tvb,
                                    Offset, 8, ENC_BIG_ENDIAN);
                                Offset +=8;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_PortNumber, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_portState, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logMinDelayReqInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                dissect_ptp_v2_timeInterval(tvb, &Offset, ptp_managementData_tree,
                                    "Peer mean path delay", hf_ptp_v2_mm_peerMeanPathDelay_ns, hf_ptp_v2_mm_peerMeanPathDelay_subns);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logAnnounceInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_announceReceiptTimeout, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logSyncInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_delayMechanism, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logMinPdelayReqInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_versionNumber, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                break;
                            }
                            case PTP_V2_MM_ID_PRIORITY1:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_priority1, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_PRIORITY2:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_priority2, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_DOMAIN:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_domainNumber, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_SLAVE_ONLY:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_SO, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_LOG_ANNOUNCE_INTERVAL:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logAnnounceInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_ANNOUNCE_RECEIPT_TIMEOUT:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_announceReceiptTimeout, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_LOG_SYNC_INTERVAL:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logSyncInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_VERSION_NUMBER:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_versionNumber, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_ENABLE_PORT:
                            {
                                /* no data */
                                break;
                            }
                            case PTP_V2_MM_ID_DISABLE_PORT:
                            {
                                /* no data */
                                break;
                            }
                            case PTP_V2_MM_ID_TIME:
                            {

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_currentTime_s, tvb,
                                            Offset, 6, ENC_BIG_ENDIAN);

                                Offset +=6;
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_currentTime_ns, tvb,
                                            Offset, 4, ENC_BIG_ENDIAN);
                                break;
                            }
                            case PTP_V2_MM_ID_CLOCK_ACCURACY:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockAccuracy, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_UTC_PROPERTIES:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_currentUtcOffset, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_LI_61, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_LI_59, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_UTCV, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_TRACEABILITY_PROPERTIES:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_TTRA, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_FTRA, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);

                                break;
                            }
                            case PTP_V2_MM_ID_TIMESCALE_PROPERTIES:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_PTP, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_timesource, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                break;
                            }
                            case PTP_V2_MM_ID_UNICAST_NEGOTIATION_ENABLE:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_ucEN, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_PATH_TRACE_LIST:
                            {
                                uint16_t i = 0;
                                /* one or more ClockIdentity */
                                for (i = 0; i < (tlv_length / 8); i++)
                                {
                                    proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockidentity, tvb,
                                        Offset, 8, ENC_BIG_ENDIAN);
                                }

                                break;
                            }
                            case PTP_V2_MM_ID_PATH_TRACE_ENABLE:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_ptEN, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);

                                break;
                            }
                            case PTP_V2_MM_ID_GRANDMASTER_CLUSTER_TABLE:
                                {
                                /* ToDo */
                                break;
                                }
                            case PTP_V2_MM_ID_UNICAST_MASTER_TABLE:
                                {
                                /* ToDo */
                                break;
                                }
                            case PTP_V2_MM_ID_UNICAST_MASTER_MAX_TABLE_SIZE:
                                {
                                /* ToDo */
                                break;
                                }
                            case PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE:
                                {
                                /* ToDo */
                                break;
                                }
                            case PTP_V2_MM_ID_ACCEPTABLE_MASTER_TABLE_ENABLED:
                                {
                                /* ToDo */
                                break;
                                }
                            case PTP_V2_MM_ID_ACCEPTABLE_MASTER_MAX_TABLE_SIZE:
                                {
                                /* ToDo */
                                break;
                                }
                            case PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_ENABLE:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_keyField, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_atEN, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                break;
                            }
                            case PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_NAME:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_keyField, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                dissect_ptp_v2_text (tvb, &Offset, ptp_managementData_tree,
                                    hf_ptp_v2_mm_displayName, hf_ptp_v2_mm_displayName_length);

                                /* Wenn Offset nicht gerade folgt noch ein pad Bit */
                                if ( (Offset - PTP_V2_MM_TLV_DATAFIELD_OFFSET) % 2 )
                                {
                                    proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_pad, tvb,
                                        Offset, 1, ENC_NA);
                                }
                                break;
                            }
                            case PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_MAX_KEY:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_maxKey, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);

                                break;
                            }
                            case PTP_V2_MM_ID_ALTERNATE_MASTER:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_transmitAlternateMulticastSync, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_numberOfAlternateMasters, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logAlternateMulticastSyncInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_ALTERNATE_TIME_OFFSET_PROPERTIES:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_keyField, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_currentOffset, tvb,
                                    Offset, 4, ENC_BIG_ENDIAN);
                                Offset +=4;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_jumpSeconds, tvb,
                                    Offset, 4, ENC_BIG_ENDIAN);
                                Offset +=4;

                                timeStamp = tvb_get_ntohl(tvb, Offset);
                                timeStamp = timeStamp << 16;
                                timeStamp = timeStamp | tvb_get_ntohs(tvb, Offset+4);

                                proto_tree_add_uint64(ptp_managementData_tree, hf_ptp_v2_mm_nextjumpSeconds, tvb,
                                    Offset, 6, timeStamp);
                                Offset +=6;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_TC_DEFAULT_DATA_SET:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockidentity, tvb,
                                    Offset, 8, ENC_BIG_ENDIAN);
                                Offset +=8;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_numberPorts, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_delayMechanism, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_primaryDomain, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                break;
                            }
                            case PTP_V2_MM_ID_TC_PORT_DATA_SET:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_clockidentity, tvb,
                                    Offset, 8, ENC_BIG_ENDIAN);
                                Offset +=8;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_PortNumber, tvb,
                                    Offset, 2, ENC_BIG_ENDIAN);
                                Offset +=2;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_faultyFlag, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logMinPdelayReqInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);
                                Offset +=1;

                                dissect_ptp_v2_timeInterval(tvb, &Offset, ptp_managementData_tree,
                                    "Peer mean path delay", hf_ptp_v2_mm_peerMeanPathDelay_ns, hf_ptp_v2_mm_peerMeanPathDelay_subns);
                                break;
                            }
                            case PTP_V2_MM_ID_PRIMARY_DOMAIN:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_primaryDomain, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_DELAY_MECHANISM:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_delayMechanism, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            case PTP_V2_MM_ID_LOG_MIN_PDELAY_REQ_INTERVAL:
                            {
                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_logMinPdelayReqInterval, tvb,
                                    Offset, 1, ENC_BIG_ENDIAN);

                                proto_tree_add_item(ptp_managementData_tree, hf_ptp_v2_mm_reserved, tvb,
                                    Offset+1, 1, ENC_NA);
                                break;
                            }
                            default:
                            {
                                /* no data */
                                break;
                            }
                        } /* switch(ptp_v2_managementId) */
                        break;
                    }
                    case PTP_V2_TLV_TYPE_MANAGEMENT_ERROR_STATUS:
                    {
                        /* there is only one error TLV */
                        uint16_t Offset = PTP_V2_MM_TLV_MANAGEMENTERRORID_OFFSET;

                        proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_managementErrorId, tvb,
                            Offset, 2, ENC_BIG_ENDIAN);
                        Offset +=2;

                        proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_managementId, tvb,
                            Offset, 2, ENC_BIG_ENDIAN);
                        Offset +=2;

                        proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_reserved, tvb,
                            Offset, 4, ENC_NA);
                        Offset +=4;

                        /* optional Field! */
                        if (Offset - PTP_V2_MM_TLV_MANAGEMENTERRORID_OFFSET + 2 < tlv_length)
                        {
                            dissect_ptp_v2_text (tvb, &Offset, ptp_tree,
                                hf_ptp_v2_mm_displayData, hf_ptp_v2_mm_displayData_length);
                        }

                        /* Wenn Offset nicht gerade folgt noch ein pad Bit */
                        if ( (Offset - PTP_V2_MM_TLV_MANAGEMENTERRORID_OFFSET) % 2 )
                        {
                            proto_tree_add_item(ptp_tree, hf_ptp_v2_mm_pad, tvb,
                                Offset, 1, ENC_NA);
                        }
                        break;
                    }
                    case PTP_V2_TLV_TYPE_ORGANIZATION_EXTENSION:
                    {
                        uint32_t org_id;
                        uint32_t subtype;
                        proto_item *smptedata_ti, *systemframerate_ti, *timeaddressflags_ti, *daylightsavingflags_ti, *leapsecondjumpflags_ti;
                        proto_tree *ptp_smptedata_tree, *ptp_framerate_tree, *ptp_timeaddress_tree, *ptp_daylightsaving_tree, *ptp_leapsecondjump_tree;
                        uint16_t Offset = PTP_V2_MM_TLV_LENGTHFIELD_OFFSET + 2;

                        proto_tree_add_item(ptp_tree, hf_ptp_v2_oe_tlv_organizationid,
                                            tvb, Offset, 3, ENC_BIG_ENDIAN);

                        org_id = tvb_get_ntoh24(tvb, Offset);
                        Offset += 3;

                        switch (org_id)
                        {
                            case OUI_SMPTE:
                            {
                            proto_tree_add_item(ptp_tree, hf_ptp_v2_oe_tlv_smpte_subtype,
                                                tvb, Offset, 3, ENC_BIG_ENDIAN);
                            subtype = tvb_get_ntoh24(tvb, Offset);
                            Offset += 3;

                                switch (subtype)
                                {
                                        case PTP_V2_OE_ORG_SMPTE_SUBTYPE_VERSION_TLV:
                                        {
                                            smptedata_ti = proto_tree_add_item(ptp_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_data, tvb, Offset, 42, ENC_NA);
                                            ptp_smptedata_tree = proto_item_add_subtree(smptedata_ti, ett_ptp_oe_smpte_data);
                                            systemframerate_ti = proto_tree_add_item(ptp_smptedata_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate, tvb, Offset, 8, ENC_NA);
                                            ptp_framerate_tree = proto_item_add_subtree(systemframerate_ti, ett_ptp_oe_smpte_framerate);
                                            proto_tree_add_item(ptp_framerate_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate_numerator, tvb, Offset, 4, ENC_BIG_ENDIAN);
                                            proto_tree_add_item(ptp_framerate_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate_denominator, tvb, Offset+4, 4, ENC_BIG_ENDIAN);
                                            Offset += 8;

                                            proto_tree_add_item(ptp_smptedata_tree, hf_ptp_v2_oe_tlv_subtype_smpte_masterlockingstatus,
                                                    tvb, Offset, 1, ENC_BIG_ENDIAN);
                                            Offset += 1;

                                            timeaddressflags_ti = proto_tree_add_item(ptp_smptedata_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags, tvb, Offset, 1, ENC_NA);
                                            ptp_timeaddress_tree = proto_item_add_subtree(timeaddressflags_ti, ett_ptp_oe_smpte_timeaddress);
                                            proto_tree_add_item(ptp_timeaddress_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags_drop, tvb, Offset, 1, ENC_BIG_ENDIAN);
                                            proto_tree_add_item(ptp_timeaddress_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags_color, tvb, Offset, 1, ENC_BIG_ENDIAN);
                                            Offset += 1;

                                            proto_tree_add_item(ptp_smptedata_tree, hf_ptp_v2_oe_tlv_subtype_smpte_currentlocaloffset,
                                                    tvb, Offset, 4, ENC_BIG_ENDIAN);
                                            Offset += 4;

                                            proto_tree_add_item(ptp_smptedata_tree, hf_ptp_v2_oe_tlv_subtype_smpte_jumpseconds,
                                                    tvb, Offset, 4, ENC_BIG_ENDIAN);
                                            Offset += 4;

                                            proto_tree_add_item(ptp_smptedata_tree, hf_ptp_v2_oe_tlv_subtype_smpte_timeofnextjump,
                                                    tvb, Offset, 6, ENC_BIG_ENDIAN);
                                            Offset += 6;

                                            proto_tree_add_item(ptp_smptedata_tree, hf_ptp_v2_oe_tlv_subtype_smpte_timeofnextjam,
                                                    tvb, Offset, 6, ENC_BIG_ENDIAN);
                                            Offset += 6;

                                            proto_tree_add_item(ptp_smptedata_tree, hf_ptp_v2_oe_tlv_subtype_smpte_timeofpreviousjam,
                                                    tvb, Offset, 6, ENC_BIG_ENDIAN);
                                            Offset += 6;

                                            proto_tree_add_item(ptp_smptedata_tree, hf_ptp_v2_oe_tlv_subtype_smpte_previousjamlocaloffset,
                                                    tvb, Offset, 4, ENC_BIG_ENDIAN);
                                            Offset += 4;

                                            daylightsavingflags_ti = proto_tree_add_item(ptp_smptedata_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving, tvb, Offset, 1, ENC_NA);
                                            ptp_daylightsaving_tree = proto_item_add_subtree(daylightsavingflags_ti, ett_ptp_oe_smpte_daylightsaving);
                                            proto_tree_add_item(ptp_daylightsaving_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_current, tvb, Offset, 1, ENC_BIG_ENDIAN);
                                            proto_tree_add_item(ptp_daylightsaving_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_next, tvb, Offset, 1, ENC_BIG_ENDIAN);
                                            proto_tree_add_item(ptp_daylightsaving_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_previous, tvb, Offset, 1, ENC_BIG_ENDIAN);
                                            Offset += 1;

                                            leapsecondjumpflags_ti = proto_tree_add_item(ptp_smptedata_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_leapsecondjump, tvb, Offset, 1, ENC_NA);
                                            ptp_leapsecondjump_tree = proto_item_add_subtree(leapsecondjumpflags_ti, ett_ptp_oe_smpte_leapsecondjump);
                                            proto_tree_add_item(ptp_leapsecondjump_tree,
                                                    hf_ptp_v2_oe_tlv_subtype_smpte_leapsecondjump_change, tvb, Offset, 1, ENC_BIG_ENDIAN);
                                            break;
                                        }
                                }
                            break;
                            }
                        }
                    }
                    default:
                    {
                        break;
                    }
                } /* switch TLV Type */
            } /* case Management Message */
        } /* switch message ID */
    } /* tree */
}


/* Register the protocol with Wireshark */

void
proto_register_ptp(void)
{
    static hf_register_info hf[] = {
        /* PTPv1 fields **********************************************************/
        /* Common fields for all frames */
        { &hf_ptp_versionptp,
          { "versionPTP",           "ptp.versionptp",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_versionnetwork,
          { "versionNetwork",           "ptp.versionnetwork",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_subdomain,
          { "subdomain",           "ptp.subdomain",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_messagetype,
          { "messageType",           "ptp.messagetype",
            FT_UINT8, BASE_DEC, VALS(ptp_messagetype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sourcecommunicationtechnology,
          { "sourceCommunicationTechnology",           "ptp.sourcecommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sourceuuid,
          { "sourceUuid",           "ptp.sourceuuid",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sourceportid,
          { "sourcePortId",           "ptp.sourceportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sequenceid,
          { "sequenceId",           "ptp.sequenceid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_controlfield,
          { "controlField",           "ptp.controlfield",
            FT_UINT8, BASE_DEC, VALS(ptp_controlfield_vals), 0x00,
            NULL, HFILL }
        },
        /* THE FLAGS-FIELD */
        { &hf_ptp_flags,
          { "flags",           "ptp.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_flags_li61,
          { "PTP_LI61",           "ptp.flags.li61",
            FT_BOOLEAN, 16, NULL, PTP_FLAGS_LI61_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_flags_li59,
          { "PTP_LI59",           "ptp.flags.li59",
            FT_BOOLEAN, 16, NULL, PTP_FLAGS_LI59_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_flags_boundary_clock,
          { "PTP_BOUNDARY_CLOCK",           "ptp.flags.boundary_clock",
            FT_BOOLEAN, 16, NULL, PTP_FLAGS_BOUNDARY_CLOCK_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_flags_assist,
          { "PTP_ASSIST",           "ptp.flags.assist",
            FT_BOOLEAN, 16, NULL, PTP_FLAGS_ASSIST_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_flags_ext_sync,
          { "PTP_EXT_SYNC",           "ptp.flags.ext_sync",
            FT_BOOLEAN, 16, NULL, PTP_FLAGS_EXT_SYNC_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_flags_parent,
          { "PTP_PARENT_STATS",           "ptp.flags.parent_stats",
            FT_BOOLEAN, 16, NULL, PTP_FLAGS_PARENT_STATS_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_flags_sync_burst,
          { "PTP_SYNC_BURST",           "ptp.flags.sync_burst",
            FT_BOOLEAN, 16, NULL, PTP_FLAGS_SYNC_BURST_BITMASK,
            NULL, HFILL }
        },
        /* END OF THE FLAG-FIELD */

        /* offsets for ptp_sync and delay_req (=sdr) messages */
        { &hf_ptp_sdr_origintimestamp,
          { "originTimestamp",           "ptp.sdr.origintimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_origintimestamp_seconds,
          { "originTimestamp (seconds)",           "ptp.sdr.origintimestamp_seconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_origintimestamp_nanoseconds,
          { "originTimestamp (nanoseconds)",           "ptp.sdr.origintimestamp_nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_epochnumber,
          { "epochNumber",           "ptp.sdr.epochnumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_currentutcoffset,
          { "currentUTCOffset",           "ptp.sdr.currentutcoffset",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmastercommunicationtechnology,
          { "grandmasterCommunicationTechnology",           "ptp.sdr.grandmastercommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmasterclockuuid,
          { "grandMasterClockUuid",           "ptp.sdr.grandmasterclockuuid",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmasterportid,
          { "grandmasterPortId",           "ptp.sdr.grandmasterportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmastersequenceid,
          { "grandmasterSequenceId",           "ptp.sdr.grandmastersequenceid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmasterclockstratum,
          { "grandmasterClockStratum",           "ptp.sdr.grandmasterclockstratum",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmasterclockidentifier,
          { "grandmasterClockIdentifier",           "ptp.sdr.grandmasterclockidentifier",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmasterclockvariance,
          { "grandmasterClockVariance",           "ptp.sdr.grandmasterclockvariance",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmasterpreferred,
          { "grandmasterPreferred",           "ptp.sdr.grandmasterpreferred",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_grandmasterisboundaryclock,
          { "grandmasterIsBoundaryClock",           "ptp.sdr.grandmasterisboundaryclock",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_syncinterval,
          { "syncInterval",           "ptp.sdr.syncinterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_localclockvariance,
          { "localClockVariance",           "ptp.sdr.localclockvariance",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_localstepsremoved,
          { "localStepsRemoved",           "ptp.sdr.localstepsremoved",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_localclockstratum,
          { "localClockStratum",           "ptp.sdr.localclockstratum",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_localclockidentifier,
          { "localClockIdentifier",           "ptp.sdr.localclockidentifier",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_parentcommunicationtechnology,
          { "parentCommunicationTechnology",           "ptp.sdr.parentcommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_parentuuid,
          { "parentUuid",           "ptp.sdr.parentuuid",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_parentportfield,
          { "parentPortField",           "ptp.sdr.parentportfield",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_estimatedmastervariance,
          { "estimatedMasterVariance",           "ptp.sdr.estimatedmastervariance",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_estimatedmasterdrift,
          { "estimatedMasterDrift",           "ptp.sdr.estimatedmasterdrift",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_sdr_utcreasonable,
          { "utcReasonable",           "ptp.sdr.utcreasonable",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        /* offsets for follow_up (=fu) messages */
        { &hf_ptp_fu_associatedsequenceid,
          { "associatedSequenceId",           "ptp.fu.associatedsequenceid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_fu_preciseorigintimestamp,
          { "preciseOriginTimestamp",    "ptp.fu.preciseorigintimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_fu_preciseorigintimestamp_seconds,
          { "preciseOriginTimestamp (seconds)",    "ptp.fu.preciseorigintimestamp_seconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_fu_preciseorigintimestamp_nanoseconds,
          { "preciseOriginTimestamp (nanoseconds)",           "ptp.fu.preciseorigintimestamp_nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* offsets for delay_resp (=dr) messages */
        { &hf_ptp_dr_delayreceipttimestamp,
          { "delayReceiptTimestamp",           "ptp.dr.delayreceipttimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_dr_delayreceipttimestamp_seconds,
          { "delayReceiptTimestamp (Seconds)",           "ptp.dr.delayreceipttimestamp_seconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_dr_delayreceipttimestamp_nanoseconds,
          { "delayReceiptTimestamp (nanoseconds)",           "ptp.dr.delayreceipttimestamp_nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_dr_requestingsourcecommunicationtechnology,
          { "requestingSourceCommunicationTechnology",    "ptp.dr.requestingsourcecommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_dr_requestingsourceuuid,
          { "requestingSourceUuid",           "ptp.dr.requestingsourceuuid",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_dr_requestingsourceportid,
          { "requestingSourcePortId",           "ptp.dr.requestingsourceportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_dr_requestingsourcesequenceid,
          { "requestingSourceSequenceId",           "ptp.dr.requestingsourcesequenceid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* offsets for management (=mm) messages */
        { &hf_ptp_mm_targetcommunicationtechnology,
          { "targetCommunicationTechnology",           "ptp.mm.targetcommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_targetuuid,
          { "targetUuid",           "ptp.mm.targetuuid",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_targetportid,
          { "targetPortId",           "ptp.mm.targetportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_startingboundaryhops,
          { "startingBoundaryHops",           "ptp.mm.startingboundaryhops",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_boundaryhops,
          { "boundaryHops",           "ptp.mm.boundaryhops",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_managementmessagekey,
          { "managementMessageKey",           "ptp.mm.managementmessagekey",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_managementMessageKey_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parameterlength,
          { "parameterLength",           "ptp.mm.parameterlength",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* parameterlength > 0 */
#if 0
        { &hf_ptp_mm_messageparameters,
          { "messageParameters",           "ptp.mm.messageparameters",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        /* ptp_mm_clock_identity (parameterlength = 64) */
        { &hf_ptp_mm_clock_identity_clockcommunicationtechnology,
          { "clockCommunicationTechnology",           "ptp.mm.clock.identity.clockcommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_clock_identity_clockuuidfield,
          { "clockUuidField",           "ptp.mm.clock.identity.clockuuidfield",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_clock_identity_clockportfield,
          { "clockPortField",           "ptp.mm.clock.identity.clockportfield",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_clock_identity_manufactureridentity,
          { "manufacturerIdentity",           "ptp.mm.clock.identity.manufactureridentity",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },

        /* ptp_mm_initialize_clock (parameterlength = 4) */
        { &hf_ptp_mm_initialize_clock_initialisationkey,
          { "initialisationKey",           "ptp.mm.initialize.clock.initialisationkey",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_set_subdomain (parameterlength = 16) */
        { &hf_ptp_mm_set_subdomain_subdomainname,
          { "subdomainName",           "ptp.mm.set.subdomain.subdomainname",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_default_data_set (parameterlength = 76) */
        { &hf_ptp_mm_default_data_set_clockcommunicationtechnology,
          { "clockCommunicationTechnology",           "ptp.mm.default.data.set.clockcommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_clockuuidfield,
          { "clockUuidField",           "ptp.mm.default.data.set.clockuuidfield",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_clockportfield,
          { "clockPortField",           "ptp.mm.default.data.set.clockportfield",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_clockstratum,
          { "clockStratum",           "ptp.mm.default.data.set.clockstratum",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_clockidentifier,
          { "clockIdentifier",           "ptp.mm.default.data.set.clockidentifier",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_clockvariance,
          { "clockVariance",           "ptp.mm.default.data.set.clockvariance",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_clockfollowupcapable,
          { "clockFollowupCapable",           "ptp.mm.default.data.set.clockfollowupcapable",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_preferred,
          { "preferred",           "ptp.mm.default.data.set.preferred",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_initializable,
          { "initializable",           "ptp.mm.default.data.set.initializable",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_externaltiming,
          { "externalTiming",           "ptp.mm.default.data.set.externaltiming",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_isboundaryclock,
          { "isBoundaryClock",           "ptp.mm.default.data.set.isboundaryclock",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_syncinterval,
          { "syncInterval",           "ptp.mm.default.data.set.syncinterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_subdomainname,
          { "subDomainName",           "ptp.mm.default.data.set.subdomainname",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_numberports,
          { "numberPorts",           "ptp.mm.default.data.set.numberports",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_default_data_set_numberforeignrecords,
          { "numberForeignRecords",           "ptp.mm.default.data.set.numberforeignrecords",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_update_default_data_set (parameterlength = 36) */
        { &hf_ptp_mm_update_default_data_set_clockstratum,
          { "clockStratum",           "ptp.mm.update.default.data.set.clockstratum",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_update_default_data_set_clockidentifier,
          { "clockIdentifier",           "ptp.mm.update.default.data.set.clockidentifier",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_update_default_data_set_clockvariance,
          { "clockVariance",           "ptp.mm.update.default.data.set.clockvariance",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_update_default_data_set_preferred,
          { "preferred",           "ptp.mm.update.default.data.set.preferred",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_update_default_data_set_syncinterval,
          { "syncInterval",           "ptp.mm.update.default.data.set.syncinterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_update_default_data_set_subdomainname,
          { "subdomainName",           "ptp.mm.update.default.data.set.subdomainname",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_current_data_set (parameterlength = 20) */
        { &hf_ptp_mm_current_data_set_stepsremoved,
          { "stepsRemoved",           "ptp.mm.current.data.set.stepsremoved",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_current_data_set_offsetfrommaster,
          { "offsetFromMaster",           "ptp.mm.current.data.set.offsetfrommaster",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_current_data_set_offsetfrommasterseconds,
          { "offsetFromMasterSeconds",           "ptp.mm.current.data.set.offsetfrommasterseconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_current_data_set_offsetfrommasternanoseconds,
          { "offsetFromMasterNanoseconds",           "ptp.mm.current.data.set.offsetfrommasternanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_current_data_set_onewaydelay,
          { "oneWayDelay",           "ptp.mm.current.data.set.onewaydelay",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_current_data_set_onewaydelayseconds,
          { "oneWayDelaySeconds",           "ptp.mm.current.data.set.onewaydelayseconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_current_data_set_onewaydelaynanoseconds,
          { "oneWayDelayNanoseconds",           "ptp.mm.current.data.set.onewaydelaynanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_parent_data_set (parameterlength = 90) */
        { &hf_ptp_mm_parent_data_set_parentcommunicationtechnology,
          { "parentCommunicationTechnology",           "ptp.mm.parent.data.set.parentcommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_parentuuid,
          { "parentUuid",           "ptp.mm.parent.data.set.parentuuid",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_parentportid,
          { "parentPortId",           "ptp.mm.parent.data.set.parentportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_parentlastsyncsequencenumber,
          { "parentLastSyncSequenceNumber",           "ptp.mm.parent.data.set.parentlastsyncsequencenumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_parentfollowupcapable,
          { "parentFollowupCapable",           "ptp.mm.parent.data.set.parentfollowupcapable",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_parentexternaltiming,
          { "parentExternalTiming",           "ptp.mm.parent.data.set.parentexternaltiming",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_parentvariance,
          { "parentVariance",           "ptp.mm.parent.data.set.parentvariance",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_parentstats,
          { "parentStats",           "ptp.mm.parent.data.set.parentstats",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_observedvariance,
          { "observedVariance",           "ptp.mm.parent.data.set.observedvariance",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_observeddrift,
          { "observedDrift",           "ptp.mm.parent.data.set.observeddrift",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_utcreasonable,
          { "utcReasonable",           "ptp.mm.parent.data.set.utcreasonable",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmastercommunicationtechnology,
          { "grandmasterCommunicationTechnology",    "ptp.mm.parent.data.set.grandmastercommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmasteruuidfield,
          { "grandmasterUuidField",           "ptp.mm.parent.data.set.grandmasteruuidfield",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmasterportidfield,
          { "grandmasterPortIdField",           "ptp.mm.parent.data.set.grandmasterportidfield",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmasterstratum,
          { "grandmasterStratum",           "ptp.mm.parent.data.set.grandmasterstratum",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmasteridentifier,
          { "grandmasterIdentifier",           "ptp.mm.parent.data.set.grandmasteridentifier",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmastervariance,
          { "grandmasterVariance",           "ptp.mm.parent.data.set.grandmastervariance",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmasterpreferred,
          { "grandmasterPreferred",           "ptp.mm.parent.data.set.grandmasterpreferred",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmasterisboundaryclock,
          { "grandmasterIsBoundaryClock",           "ptp.mm.parent.data.set.grandmasterisboundaryclock",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_parent_data_set_grandmastersequencenumber,
          { "grandmasterSequenceNumber",           "ptp.mm.parent.data.set.grandmastersequencenumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_port_data_set (parameterlength = 52) */
        { &hf_ptp_mm_port_data_set_returnedportnumber,
          { "returnedPortNumber",           "ptp.mm.port.data.set.returnedportnumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_portstate,
          { "portState",           "ptp.mm.port.data.set.portstate",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_lastsynceventsequencenumber,
          { "lastSyncEventSequenceNumber",           "ptp.mm.port.data.set.lastsynceventsequencenumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_lastgeneraleventsequencenumber,
          { "lastGeneralEventSequenceNumber",           "ptp.mm.port.data.set.lastgeneraleventsequencenumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_portcommunicationtechnology,
          { "portCommunicationTechnology",           "ptp.mm.port.data.set.portcommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_portuuidfield,
          { "portUuidField",           "ptp.mm.port.data.set.portuuidfield",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_portidfield,
          { "portIdField",           "ptp.mm.port.data.set.portidfield",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_burstenabled,
          { "burstEnabled",           "ptp.mm.port.data.set.burstenabled",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_subdomainaddressoctets,
          { "subdomainAddressOctets",           "ptp.mm.port.data.set.subdomainaddressoctets",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_eventportaddressoctets,
          { "eventPortAddressOctets",           "ptp.mm.port.data.set.eventportaddressoctets",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_generalportaddressoctets,
          { "generalPortAddressOctets",           "ptp.mm.port.data.set.generalportaddressoctets",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_subdomainaddress,
          { "subdomainAddress",           "ptp.mm.port.data.set.subdomainaddress",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_eventportaddress,
          { "eventPortAddress",           "ptp.mm.port.data.set.eventportaddress",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_port_data_set_generalportaddress,
          { "generalPortAddress",           "ptp.mm.port.data.set.generalportaddress",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_global_time_data_set (parameterlength = 24) */
        { &hf_ptp_mm_global_time_data_set_localtime,
          { "localTime",           "ptp.mm.global.time.data.set.localtime",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_global_time_data_set_localtimeseconds,
          { "localTimeSeconds",           "ptp.mm.global.time.data.set.localtimeseconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_global_time_data_set_localtimenanoseconds,
          { "localTimeNanoseconds",           "ptp.mm.global.time.data.set.localtimenanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_global_time_data_set_currentutcoffset,
          { "currentUtcOffset",           "ptp.mm.global.time.data.set.currentutcoffset",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_global_time_data_set_leap59,
          { "leap59",           "ptp.mm.global.time.data.set.leap59",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_global_time_data_set_leap61,
          { "leap61",           "ptp.mm.global.time.data.set.leap61",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_global_time_data_set_epochnumber,
          { "epochNumber",           "ptp.mm.global.time.data.set.epochnumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_update_global_time_properties (parameterlength = 16) */
        { &hf_ptp_mm_update_global_time_properties_currentutcoffset,
          { "currentUtcOffset",           "ptp.mm.update.global.time.properties.currentutcoffset",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_update_global_time_properties_leap59,
          { "leap59",           "ptp.mm.update.global.time.properties.leap59",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_mm_update_global_time_properties_leap61,
          { "leap61",           "ptp.mm.update.global.time.properties.leap61",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
#if 0
        { &hf_ptp_mm_update_global_time_properties_epochnumber,
          { "epochNumber",           "ptp.mm.update.global.time.properties.epochnumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        /* ptp_mm_get_foreign_data_set (parameterlength = 4) */
        { &hf_ptp_mm_get_foreign_data_set_recordkey,
          { "recordKey",           "ptp.mm.get.foreign.data.set.recordkey",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_foreign_data_set (parameterlength = 28) */
        { &hf_ptp_mm_foreign_data_set_returnedportnumber,
          { "returnedPortNumber",           "ptp.mm.foreign.data.set.returnedportnumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_foreign_data_set_returnedrecordnumber,
          { "returnedRecordNumber",           "ptp.mm.foreign.data.set.returnedrecordnumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_foreign_data_set_foreignmastercommunicationtechnology,
          { "foreignMasterCommunicationTechnology",
            "ptp.mm.foreign.data.set.foreignmastercommunicationtechnology",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_communicationid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_foreign_data_set_foreignmasteruuidfield,
          { "foreignMasterUuidField",           "ptp.mm.foreign.data.set.foreignmasteruuidfield",
            FT_ETHER, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_foreign_data_set_foreignmasterportidfield,
          { "foreignMasterPortIdField",           "ptp.mm.foreign.data.set.foreignmasterportidfield",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_foreign_data_set_foreignmastersyncs,
          { "foreignMasterSyncs",           "ptp.mm.foreign.data.set.foreignmastersyncs",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_set_sync_interval (parameterlength = 4) */
        { &hf_ptp_mm_set_sync_interval_syncinterval,
          { "syncInterval",           "ptp.mm.set.sync.interval.syncinterval",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* ptp_mm_set_time (parameterlength = 8) */
        { &hf_ptp_mm_set_time_localtime,
          { "localtime",           "ptp.mm.set.time.localtime",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_set_time_localtimeseconds,
          { "localtimeSeconds",           "ptp.mm.set.time.localtimeseconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_mm_set_time_localtimenanoseconds,
          { "localTimeNanoseconds",           "ptp.mm.set.time.localtimenanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },




        /* PTPv2 fields **********************************************************/
        /* Common fields for all frames */
        { &hf_ptp_v2_majorsdoid,
          { "majorSdoId",           "ptp.v2.majorsdoid",
            FT_UINT8, BASE_HEX, VALS(ptpv2_majorsdoid_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_ptp_v2_messagetype,
          { "messageType",           "ptp.v2.messagetype",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, & ptp_v2_messagetype_vals_ext, 0x0F,
            NULL, HFILL }
        },
        { &hf_ptp_v2_minorversionptp,
          { "minorVersionPTP",             "ptp.v2.minorversionptp",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_ptp_v2_versionptp,
          { "versionPTP",           "ptp.v2.versionptp",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_ptp_v2_messagelength,
          { "messageLength",           "ptp.v2.messagelength",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_minorsdoid,
          { "minorSdoId",               "ptp.v2.minorsdoid",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_domainnumber,
          { "domainNumber",           "ptp.v2.domainnumber",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags,
          { "flags",           "ptp.v2.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_alternatemaster,
          { "PTP_ALTERNATE_MASTER",     "ptp.v2.flags.alternatemaster",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_ALTERNATE_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_twostep,
          { "PTP_TWO_STEP",           "ptp.v2.flags.twostep",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_TWO_STEP_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_unicast,
          { "PTP_UNICAST",           "ptp.v2.flags.unicast",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_UNICAST_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_specific1,
          { "PTP profile Specific 1",           "ptp.v2.flags.specific1",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_SPECIFIC1_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_specific2,
          { "PTP profile Specific 2",           "ptp.v2.flags.specific2",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_SPECIFIC2_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_security,
          { "PTP_SECURITY",           "ptp.v2.flags.security",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_SECURITY_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_li61,
          { "PTP_LI_61",           "ptp.v2.flags.li61",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_LI61_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_li59,
          { "PTP_LI_59",           "ptp.v2.flags.li59",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_LI59_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_utcoffsetvalid,
          { "PTP_UTC_REASONABLE",           "ptp.v2.flags.utcreasonable",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_UTC_OFFSET_VALID_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_ptptimescale,
          { "PTP_TIMESCALE",           "ptp.v2.flags.timescale",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_PTP_TIMESCALE_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_timetraceable,
          { "TIME_TRACEABLE",           "ptp.v2.flags.timetraceable",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_TIME_TRACEABLE_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_frequencytraceable,
          { "FREQUENCY_TRACEABLE",           "ptp.v2.flags.frequencytraceable",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_FREQUENCY_TRACEABLE_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_flags_synchronizationUncertain,
          { "SYNCHRONIZATION_UNCERTAIN",           "ptp.v2.flags.synchronizationUncertain",
            FT_BOOLEAN, 16, NULL, PTP_V2_FLAGS_SYNCHRONIZATION_UNCERTAIN_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_messagetypespecific,
          { "messageTypeSpecific",           "ptp.v2.messagetypespecific",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_correction,
          { "correctionNs",              "ptp.v2.correction.ns",
            FT_INT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_correctionsubns,
          { "correctionSubNs",           "ptp.v2.correction.subns",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_clockidentity,
          { "ClockIdentity",           "ptp.v2.clockidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_clockidentity_manuf,
          { "MAC Vendor",       "ptp.v2.clockidentity_manuf",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sourceportid,
          { "SourcePortID",           "ptp.v2.sourceportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sequenceid,
          { "sequenceId",           "ptp.v2.sequenceid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_controlfield_default,
          { "controlField",           "ptp.v2.controlfield",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_controlfield,
          { "controlField",           "ptp.v2.controlfield",
            FT_UINT8, BASE_DEC, VALS(ptp_controlfield_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_logmessageperiod,
          { "logMessagePeriod",           "ptp.v2.logmessageperiod",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_Announce (=an) messages */
#if 0
        { &hf_ptp_v2_an_origintimestamp,
          { "originTimestamp",           "ptp.v2.an.origintimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_an_origintimestamp_seconds,
          { "originTimestamp (seconds)",           "ptp.v2.an.origintimestamp.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_origintimestamp_nanoseconds,
          { "originTimestamp (nanoseconds)",           "ptp.v2.an.origintimestamp.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_origincurrentutcoffset,
          { "originCurrentUTCOffset",           "ptp.v2.an.origincurrentutcoffset",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_timesource,
          { "TimeSource",           "ptp.v2.timesource",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ptp_v2_timeSource_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_localstepsremoved,
          { "localStepsRemoved",           "ptp.v2.an.localstepsremoved",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_grandmasterclockidentity,
          { "grandmasterClockIdentity",           "ptp.v2.an.grandmasterclockidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_grandmasterclockclass,
          { "grandmasterClockClass",           "ptp.v2.an.grandmasterclockclass",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_grandmasterclockaccuracy,
          { "grandmasterClockAccuracy",           "ptp.v2.an.grandmasterclockaccuracy",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ptp_v2_clockAccuracy_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_grandmasterclockvariance,
          { "grandmasterClockVariance",           "ptp.v2.an.grandmasterclockvariance",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_priority1,
          { "priority1",           "ptp.v2.an.priority1",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_priority2,
          { "priority2",           "ptp.v2.an.priority2",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_Announce TLVs */
        { &hf_ptp_v2_an_tlv_tlvtype,
          { "tlvType", "ptp.v2.an.tlvType",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ptp_v2_TLV_type_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_tlv_lengthfield,
          { "lengthField", "ptp.v2.an.lengthField",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* Fields for ORGANIZATION_EXTENSION TLV */
        { &hf_ptp_v2_oe_tlv_organizationid,
          { "organizationId", "ptp.v2.an.oe.organizationId",
            FT_UINT24, BASE_OUI, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_organizationsubtype,
          { "organizationSubType", "ptp.v2.an.oe.organizationSubType",
            FT_UINT24, BASE_HEX, VALS(ptp_v2_org_iee_c37_238_subtype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_2017_organizationsubtype,
          { "organizationSubType", "ptp.v2.an.oe.organizationSubType",
            FT_UINT24, BASE_HEX, VALS(ptp_v2_org_iee_c37_238_2017_subtype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_datafield,
          { "dataField", "ptp.v2.an.oe.dataField",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Fields for CERN White Rabbit TLV (OE TLV subtype) */
        { &hf_ptp_v2_an_tlv_oe_cern_subtype,
          { "organizationSubType", "ptp.v2.an.oe.organizationSubType",
            FT_UINT24, BASE_HEX, VALS(ptp_v2_org_cern_subtype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_tlv_oe_cern_wrMessageID,
          { "wrMessageID", "ptp.v2.an.oe.cern.wr.wrMessageID",
            FT_UINT16, BASE_HEX, VALS(ptp_v2_org_cern_wrMessageID_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_tlv_oe_cern_wrFlags,
          { "wrFlags", "ptp.v2.an.oe.cern.wr.wrFlags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
         { &hf_ptp_v2_an_tlv_oe_cern_wrFlags_wrConfig,
           { "wrConfig",           "ptp.v2.an.oe.cern.wr.wrFlags.wrConfig",
             FT_UINT16, BASE_HEX, VALS(ptp_v2_tlv_oe_cern_wrFlags_wrConfig_vals), PTP_V2_TLV_OE_CERN_WRFLAGS_WRCONFIG_BITMASK,
             NULL, HFILL }
         },
        { &hf_ptp_v2_an_tlv_oe_cern_wrFlags_calibrated,
          { "calibrated",           "ptp.v2.an.oe.cern.wr.wrFlags.calibrated",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_OE_CERN_WRFLAGS_CALIBRATED_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_an_tlv_oe_cern_wrFlags_wrModeOn,
          { "wrModeOn",           "ptp.v2.an.oe.cern.wr.wrFlags.wrModeOn",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_OE_CERN_WRFLAGS_WRMODEON_BITMASK,
            NULL, HFILL }
        },
        /* Fields for IEEE_C37_238 TLV (OE TLV subtype) */
        { &hf_ptp_v2_oe_tlv_subtype_c37238tlv_grandmasterid,
          { "grandmasterID", "ptp.v2.an.oe.grandmasterID",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_c37238tlv_grandmastertimeinaccuracy,
          { "grandmasterTimeInaccuracy (nanoseconds)", "ptp.v2.an.oe.grandmasterTimeInaccuracy",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_c37238tlv_networktimeinaccuracy,
          { "networkTimeInaccuracy (nanoseconds)", "ptp.v2.an.oe.networkTimeInaccuracy",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_c37238tlv_reserved,
          { "reserved", "ptp.v2.an.oe.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        /* Additional fields in C37.238-2017 compared to C37.238-2011 */
        { &hf_ptp_v2_oe_tlv_subtype_c372382017tlv_reserved,
          { "reserved", "ptp.v2.an.oe.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_c37238tlv_totaltimeinaccuracy,
            { "totalTimeInaccuracy (nanoseconds)", "ptp.v2.an.oe.totalTimeInaccuracy",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
        },
        /* Fields for ALTERNATE_TIME_OFFSET_INDICATOR TLV */
        { &hf_ptp_v2_atoi_tlv_keyfield,
          { "keyField", "ptp.v2.an.atoi.keyField",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_atoi_tlv_currentoffset,
          { "currentOffset", "ptp.v2.an.atoi.currentOffset",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_atoi_tlv_jumpseconds,
          { "jumpSeconds", "ptp.v2.an.atoi.jumpSeconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_atoi_tlv_timeofnextjump,
          { "timeOfNextJump", "ptp.v2.an.atoi.timeOfNextJump",
            FT_INT48, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_atoi_tlv_displayname,
          { "displayName", "ptp.v2.an.atoi.displayName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_atoi_tlv_displayname_length,
          { "length",           "ptp.v2.an.atoi.displayName.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* Field for Path Trace TLV */
        { &hf_ptp_v2_an_tlv_pathsequence,
          { "PathSequence", "ptp.v2.an.pathsequence",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for undissected TLV */
        { &hf_ptp_v2_an_tlv_data,
          { "data",           "ptp.v2.an.tlv.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_Sync AND PTP_DelayRequest (=sdr) messages */
#if 0
        { &hf_ptp_v2_sdr_origintimestamp,
          { "originTimestamp",           "ptp.v2.sdr.origintimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_sdr_origintimestamp_seconds,
          { "originTimestamp (seconds)",           "ptp.v2.sdr.origintimestamp.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sdr_origintimestamp_nanoseconds,
          { "originTimestamp (nanoseconds)",           "ptp.v2.sdr.origintimestamp.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        { &hf_ptp_v2_sync_reserved,
          { "reserved",           "ptp.v2.sync.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_Follow_Up (=fu) messages */
#if 0
        { &hf_ptp_v2_fu_preciseorigintimestamp,
          { "preciseOriginTimestamp",           "ptp.v2.fu.preciseorigintimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_fu_preciseorigintimestamp_seconds,
          { "preciseOriginTimestamp (seconds)",           "ptp.v2.fu.preciseorigintimestamp.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_fu_preciseorigintimestamp_nanoseconds,
          { "preciseOriginTimestamp (nanoseconds)",           "ptp.v2.fu.preciseorigintimestamp.nanoseconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_fu_preciseorigintimestamp_32bit,
          { "preciseOriginTimestamp (32bit)",           "ptp.v2.fu.preciseorigintimestamp.32bit",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Fields for PTP_Follow_up TLVs */
        { &hf_ptp_as_fu_tlv_tlvtype,
          { "tlvType", "ptp.as.fu.tlvType",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ptp_v2_TLV_type_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_lengthfield,
          { "lengthField", "ptp.as.fu.lengthField",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_organization_id,
          { "organizationId", "ptp.as.fu.organizationId",
            FT_UINT24, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_organization_subtype,
          { "OrganizationSubType", "ptp.as.fu.organizationSubType",
            FT_INT24, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_cumulative_scaled_rate_offset,
          { "cumulativeScaledRateOffset", "ptp.as.fu.cumulativeScaledRateOffset",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_cumulative_rate_ratio,
          { "cumulativeRateRatio", "ptp.as.fu.cumulativeRateRatio",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_gm_base_indicator,
          { "gmTimeBaseIndicator", "ptp.as.fu.gmTimeBaseIndicator",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_last_gm_phase_change,
          { "lastGMPhaseChange", "ptp.as.fu.lastGmPhaseChange",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_fu_tlv_scaled_last_gm_freq_change,
          { "scaledLastGmFreqChange", "ptp.as.fu.scaledLastGmFreqChange",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_DelayResponse (=dr) messages */
#if 0
        { &hf_ptp_v2_dr_receivetimestamp,
          { "receiveTimestamp",           "ptp.v2.dr.receivetimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_dr_receivetimestamp_seconds,
          { "receiveTimestamp (seconds)",           "ptp.v2.dr.receivetimestamp.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_dr_receivetimestamp_nanoseconds,
          { "receiveTimestamp (nanoseconds)",           "ptp.v2.dr.receivetimestamp.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_dr_requestingportidentity,
          { "requestingSourcePortIdentity",           "ptp.v2.dr.requestingsourceportidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_dr_requestingsourceportid,
          { "requestingSourcePortId",           "ptp.v2.dr.requestingsourceportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_PDelayRequest (=pdrq) messages */
#if 0
        { &hf_ptp_v2_pdrq_origintimestamp,
          { "originTimestamp",           "ptp.v2.pdrq.origintimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_pdrq_origintimestamp_seconds,
          { "originTimestamp (seconds)",           "ptp.v2.pdrq.origintimestamp.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_pdrq_origintimestamp_nanoseconds,
          { "originTimestamp (nanoseconds)",           "ptp.v2.pdrq.origintimestamp.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_PDelayResponse (=pdrs) messages */
#if 0
        { &hf_ptp_v2_pdrs_requestreceipttimestamp,
          { "requestreceiptTimestamp",           "ptp.v2.pdrs.requestreceipttimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_pdrs_requestreceipttimestamp_seconds,
          { "requestreceiptTimestamp (seconds)",           "ptp.v2.pdrs.requestreceipttimestamp.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_pdrs_requestreceipttimestamp_nanoseconds,
          { "requestreceiptTimestamp (nanoseconds)",           "ptp.v2.pdrs.requestreceipttimestamp.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_pdrs_requestingportidentity,
          { "requestingSourcePortIdentity",           "ptp.v2.pdrs.requestingportidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_pdrs_requestingsourceportid,
          { "requestingSourcePortId",           "ptp.v2.pdrs.requestingsourceportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_PDelayResponseFollowUp (=pdfu) messages */
#if 0
        { &hf_ptp_v2_pdfu_responseorigintimestamp,
          { "responseOriginTimestamp",           "ptp.v2.pdfu.responseorigintimestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_pdfu_responseorigintimestamp_seconds,
          { "responseOriginTimestamp (seconds)",           "ptp.v2.pdfu.responseorigintimestamp.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_pdfu_responseorigintimestamp_nanoseconds,
          { "responseOriginTimestamp (nanoseconds)",           "ptp.v2.pdfu.responseorigintimestamp.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_pdfu_requestingportidentity,
          { "requestingSourcePortIdentity",           "ptp.v2.pdfu.requestingportidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_pdfu_requestingsourceportid,
          { "requestingSourcePortId",           "ptp.v2.pdfu.requestingsourceportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },

        /* Fields for PTP_Signalling (=sig) messages */
        { &hf_ptp_v2_sig_targetportidentity,
          { "targetPortIdentity",           "ptp.v2.sig.targetportidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_targetportid,
          { "targetPortId",                 "ptp.v2.sig.targetportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_tlvType,
          { "tlvType",                      "ptp.v2.sig.tlv.tlvType",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ptp_v2_TLV_type_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_lengthField,
          { "lengthField",                  "ptp.v2.sig.tlv.lengthField",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_data,
          { "data",                         "ptp.v2.sig.tlv.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_messageType,
          { "messageType",                  "ptp.v2.sig.tlv.messageType",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, & ptp_v2_messagetype_vals_ext, 0xF0,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_logInterMessagePeriod,
          { "logInterMessagePeriod",        "ptp.v2.sig.tlv.logInterMessagePeriod",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_logInterMessagePeriod_period,
          { "period",                       "ptp.v2.sig.tlv.logInterMessagePeriod.period",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_logInterMessagePeriod_rate,
          { "rate",                         "ptp.v2.sig.tlv.logInterMessagePeriod.rate",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_durationField,
          { "durationField",                "ptp.v2.sig.tlv.durationField",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_second_seconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_renewalInvited,
          { "renewalInvited",               "ptp.v2.sig.tlv.renewalInvited",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_flags2,
          { "flags",           "ptp.v2.sig.tlv.l1sync.flags",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_flags3,
          { "flags",           "ptp.v2.sig.tlv.l1sync.flags",
            FT_UINT24, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_tcr, /* Version with 2 bytes flags field */
          { "txCoherentIsRequired",           "ptp.v2.sig.tlv.l1sync.flags.tcr",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_TCR_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_tcr, /* Version with 3 bytes flags field */
          { "txCoherentIsRequired",           "ptp.v2.sig.tlv.l1sync.flags.tcr",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_TCR_BITMASK << 8,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_rcr, /* Version with 2 bytes flags field */
          { "rxCoherentIsRequired",           "ptp.v2.sig.tlv.l1sync.flags.rcr",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_RCR_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_rcr, /* Version with 3 bytes flags field */
          { "rxCoherentIsRequired",           "ptp.v2.sig.tlv.l1sync.flags.rcr",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_RCR_BITMASK << 8,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_cr, /* Version with 2 bytes flags field */
          { "congruentIsRequired",           "ptp.v2.sig.tlv.l1sync.flags.cr",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_CR_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_cr, /* Version with 3 bytes flags field */
          { "congruentIsRequired",           "ptp.v2.sig.tlv.l1sync.flags.cr",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_CR_BITMASK << 8,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_ope, /* Version with 2 bytes flags field */
          { "optParamsEnabled",           "ptp.v2.sig.tlv.l1sync.flags.ope",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_OPE_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_ope, /* Version with 3 bytes flags field */
          { "optParamsEnabled",           "ptp.v2.sig.tlv.l1sync.flags.ope",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS1_OPE_BITMASK << 8,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_itc, /* Version with 2 bytes flags field */
          { "isTxCoherent",           "ptp.v2.sig.tlv.l1sync.flags.itc",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_ITC_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_itc, /* Version with 3 bytes flags field */
          { "isTxCoherent",           "ptp.v2.sig.tlv.l1sync.flags.itc",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_ITC_BITMASK << 8,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_irc, /* Version with 2 bytes flags field */
          { "isRxCoherent",           "ptp.v2.sig.tlv.l1sync.flags.irc",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_IRC_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_irc, /* Version with 3 bytes flags field */
          { "isRxCoherent",           "ptp.v2.sig.tlv.l1sync.flags.irc",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_IRC_BITMASK << 8,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_ic, /* Version with 2 bytes flags field */
          { "isCongruent",           "ptp.v2.sig.tlv.l1sync.flags.ic",
            FT_BOOLEAN, 16, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_IC_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_ic, /* Version with 3 bytes flags field */
          { "isCongruent",           "ptp.v2.sig.tlv.l1sync.flags.ic",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_IC_BITMASK << 8,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_fov,
          { "frequencyOffsetTxValid", "ptp.v2.sig.tlv.l1sync.flags.fov",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_FOV_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_pov,
          { "phaseOffsetTxValid",    "ptp.v2.sig.tlv.l1sync.flags.pov",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_POV_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_tct,
          { "timestampsCorrectedTx", "ptp.v2.sig.tlv.l1sync.flags.tct",
            FT_BOOLEAN, 24, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_TCT_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags2_reserved,
          { "Reserved", "ptp.v2.sig.tlv.l1sync.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS2_RESERVED_ALL_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1sync_flags3_reserved,
          { "Reserved", "ptp.v2.sig.tlv.l1sync.flags.reserved",
            FT_UINT24, BASE_HEX, NULL, PTP_V2_TLV_SIG_TLV_L1SYNC_FLAGS3_RESERVED_ALL_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTx_ns,
          { "Ns",           "ptp.v2.sig.tlv.l1sync.phaseOffsetTx.ns",
            FT_INT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTx_subns,
          { "SubNs",           "ptp.v2.sig.tlv.l1sync.phaseOffsetTx.subns",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTxTimestamp_s,
          { "S",           "ptp.v2.sig.tlv.l1sync.phaseOffsetTxTimestamp.s",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_second_seconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_phaseOffsetTxTimestamp_ns,
          { "Ns",           "ptp.v2.sig.tlv.l1sync.phaseOffsetTxTimestamp.ns",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTx_ns,
          { "Ns",           "ptp.v2.sig.tlv.l1sync.freqOffsetTx.ns",
            FT_INT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTx_subns,
          { "SubNs",           "ptp.v2.sig.tlv.l1sync.freqOffsetTx.subns",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTxTimestamp_s,
          { "S",           "ptp.v2.sig.tlv.l1sync.freqOffsetTxTimestamp.s",
            FT_UINT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_second_seconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_l1syncext_freqOffsetTxTimestamp_ns,
          { "Ns",           "ptp.v2.sig.tlv.l1sync.freqOffsetTxTimestamp.ns",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_cern_subtype,
          { "organizationSubType", "ptp.v2.sig.oe.organizationSubType",
            FT_UINT24, BASE_HEX, VALS(ptp_v2_org_cern_subtype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_itut_subtype,
          { "organizationSubType", "ptp.v2.sig.oe.organizationSubType",
            FT_UINT24, BASE_HEX, VALS(ptp_v2_org_itut_subtype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_cern_wrMessageID,
          { "wrMessageID", "ptp.v2.sig.oe.cern.wr.wrMessageID",
            FT_UINT16, BASE_HEX, VALS(ptp_v2_org_cern_wrMessageID_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_cern_calSendPattern,
          { "calSendPattern", "ptp.v2.sig.oe.cern.wr.calSendPattern",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_cern_calRety,
          { "calRety", "ptp.v2.sig.oe.cern.wr.calRety",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_cern_calPeriod,
          { "calPeriod", "ptp.v2.sig.oe.cern.wr.calPeriod",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_cern_deltaTx,
          { "deltaTx", "ptp.v2.sig.oe.cern.wr.deltaTx",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_oe_tlv_cern_deltaRx,
          { "deltaRx", "ptp.v2.sig.oe.cern.wr.deltaRx",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Fields for PTP_Signalling (=sig) TLVs */
        { &hf_ptp_as_sig_tlv_tlvtype,
          { "tlvType", "ptp.as.sig.tlvType",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ptp_v2_TLV_type_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_lengthfield,
          { "lengthField", "ptp.as.sig.lengthField",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_organization_id,
          { "organizationId", "ptp.as.sig.tlv.organizationId",
            FT_UINT24, BASE_HEX, VALS(ptp_as_TLV_oid_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_organization_subtype,
          { "OrganizationSubType", "ptp.as.sig.tlv.organizationSubType",
            FT_INT24, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_link_delay_interval,
          { "linkDelayInterval", "ptp.as.sig.tlv.linkdelayinterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_time_sync_interval,
          { "timeSyncInterval", "ptp.as.sig.tlv.timesyncinterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_announce_interval,
          { "announceInterval", "ptp.as.sig.tlv.announceinterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_flags,
          { "flags",           "ptp.as.sig.tlv.flags",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_flags_comp_rate_ratio,
          { "computeNeighborRateRatio", "ptp.as.sig.tlv.flags.rateratio",
            FT_BOOLEAN, 8, NULL, PTP_AS_FLAGS_COMP_NEIGHBOR_RATE_RATIO_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_flags_comp_mean_link_delay,
          { "computeMeanLinkDelay", "ptp.as.sig.tlv.flags.meanlinkdelay",
            FT_BOOLEAN, 8, NULL, PTP_AS_FLAGS_COMP_MEAN_LINK_DELAY_BITMASK,
            NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_flags_one_step_receive_capable,
          { "oneStepReceiveCapable", "ptp.as.sig.tlv.flags.stepreceivecapable",
             FT_BOOLEAN, 8, NULL, PTP_AS_FLAGS_ONE_STEP_RECEIVE_CAPABLE,
             NULL, HFILL }
        },
        { &hf_ptp_as_sig_tlv_gptp_capable_message_interval,
          { "gptpCapableMessageInterval", "ptp.as.sig.tlv.gptpcapablemessageinterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_interface_bit_period,
          { "interfaceBitPeriod", "ptp.as.sig.tlv.interfaceBitPeriod",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_numberbits_before_timestamp,
          { "numberBitsBeforeTimestamp", "ptp.as.sig.tlv.numberBitsBeforeTimestamp",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_sig_tlv_numberbits_after_timestamp,
          { "numberBitsAfterTimestamp", "ptp.as.sig.tlv.numberBitsAfterTimestamp",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        /* Fields for PTP_Management (=mm) messages */
        { &hf_ptp_v2_mm_targetportidentity,
          { "targetPortIdentity",           "ptp.v2.mm.targetportidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_targetportid,
          { "targetPortId",           "ptp.v2.mm.targetportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_startingboundaryhops,
          { "startingBoundaryHops",           "ptp.v2.mm.startingboundaryhops",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_boundaryhops,
          { "boundaryHops",           "ptp.v2.mm.boundaryhops",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_action,
          { "action",           "ptp.v2.mm.action",
            FT_UINT8, BASE_DEC, VALS(ptp_v2_mm_action_vals), 0x0F,
            NULL, HFILL }
        },
        /* Management TLV */
        { &hf_ptp_v2_mm_tlvType,
          { "tlvType",           "ptp.v2.mm.tlvType",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &ptp_v2_TLV_type_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_lengthField,
          { "lengthField",           "ptp.v2.mm.lengthField",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_managementId,
          { "managementId",           "ptp.v2.mm.managementId",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &ptp_v2_managementID_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_data,
          { "data",           "ptp.v2.mm.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        /* Management TLV dataField */
        /* CLOCK_DESCRIPTION */
        { &hf_ptp_v2_mm_clockType,
          { "clockType",           "ptp.v2.mm.clockType",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockType_ordinaryClock,
          { "The node implements an ordinary clock", "ptp.v2.mm.clockType.OC",
            FT_BOOLEAN, 16, NULL, CLOCKTYPE_ORDINARY_CLOCK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockType_boundaryClock,
          { "The node implements a boundary clock", "ptp.v2.mm.clockType.BC",
            FT_BOOLEAN, 16, NULL, CLOCKTYPE_BOUNDARY_CLOCK,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockType_p2p_transparentClock,
          { "The node implements a peer-to-peer transparent clock", "ptp.v2.mm.clockType.p2p_TC",
            FT_BOOLEAN, 16, NULL, CLOCKTYPE_P2P_TC,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockType_e2e_transparentClock,
          { "The node implements an end-to-end transparent clock", "ptp.v2.mm.clockType.e2e_TC",
            FT_BOOLEAN, 16, NULL, CLOCKTYPE_E2E_TC,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockType_managementNode,
          { "The node implements a management node", "ptp.v2.mm.clockType.MM",
            FT_BOOLEAN, 16, NULL, CLOCKTYPE_MANAGEMENT_NODE,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockType_reserved,
          { "Reserved", "ptp.v2.mm.clockType.reserved",
            FT_BOOLEAN, 16, NULL, CLOCKTYPE_RESERVED,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_physicalLayerProtocol,
          { "physicalLayerProtocol",           "ptp.v2.mm.physicalLayerProtocol",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_physicalLayerProtocol_length,
          { "length",           "ptp.v2.mm.physicalLayerProtocol.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_physicalAddressLength,
          { "physical address length",  "ptp.v2.mm.physicalAddressLength",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_physicalAddress,
          { "physical address",  "ptp.v2.mm.physicalAddress",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_protocolAddress,
          { "protocol address",  "ptp.v2.mm.protocolAddress",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_protocolAddress_networkProtocol,
          { "network protocol",           "ptp.v2.mm.networkProtocol",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &ptp_v2_networkProtocol_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_protocolAddress_length,
          { "length",  "ptp.v2.mm.protocolAddress.length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_manufacturerIdentity,
          { "manufacturer identity",  "ptp.v2.mm.manufacturerIdentity",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_reserved,
          { "reserved",  "ptp.v2.mm.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_productDescription,
          { "product description",  "ptp.v2.mm.productDescription",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_productDescription_length,
          { "length",           "ptp.v2.mm.productDescription.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_revisionData,
          { "revision data",  "ptp.v2.mm.revisionData",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_revisionData_length,
          { "length",           "ptp.v2.mm.revisionData.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_userDescription,
          { "user description",  "ptp.v2.mm.userDescription",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_userDescription_length,
          { "length",           "ptp.v2.mm.userDescription.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_profileIdentity,
          { "profileIdentity",           "ptp.v2.mm.profileIdentity",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_pad,
          { "Pad",           "ptp.v2.mm.pad",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_initializationKey,
          { "initialization key",           "ptp.v2.mm.initializationKey",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_numberOfFaultRecords,
          { "number of fault records",  "ptp.v2.mm.numberOfFaultRecords",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
#if 0
        { &hf_ptp_v2_mm_faultRecord,
          { "fault record",  "ptp.v2.mm.faultRecord",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_mm_faultRecordLength,
          { "fault record length",           "ptp.v2.mm.faultRecordLength",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_severityCode,
          { "severity code",           "ptp.v2.mm.severityCode",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_v2_severityCode_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultName,
          { "faultName",  "ptp.v2.mm.faultName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultName_length,
          { "length",           "ptp.v2.mm.faultName.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultValue,
          { "faultValue",  "ptp.v2.mm.faultValue",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultValue_length,
          { "length",           "ptp.v2.mm.faultValue.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultDescription,
          { "faultDescription",  "ptp.v2.mm.faultDescription",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultDescription_length,
          { "length",           "ptp.v2.mm.faultDescription.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
#if 0
        { &hf_ptp_v2_mm_faultTime,
          { "Fault time", "ptp.v2.mm.faultTime",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
#endif
        { &hf_ptp_v2_mm_faultTime_s,
          { "Fault time (seconds)", "ptp.v2.mm.faultTime.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultTime_ns,
          { "Fault time (nanoseconds)", "ptp.v2.mm.faultTime.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_currentTime_s,
          { "current time (seconds)", "ptp.v2.mm.currentTime.seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_currentTime_ns,
          { "current time (nanoseconds)", "ptp.v2.mm.currentTime.nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockAccuracy,
          { "Clock accuracy",           "ptp.v2.mm.clockaccuracy",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ptp_v2_clockAccuracy_vals_ext, 0x00,
            NULL, HFILL }
        },

        { &hf_ptp_v2_mm_priority1,
          { "priority1",           "ptp.v2.mm.priority1",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_priority2,
          { "priority2",           "ptp.v2.mm.priority2",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_dds_SO,
          { "Slave only",           "ptp.v2.mm.SlaveOnly",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_TSC,
          { "Two step",           "ptp.v2.mm.twoStep",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_numberPorts,
          { "number of ports",  "ptp.v2.mm.numberPorts",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockclass,
          { "Clock class",           "ptp.v2.mm.clockclass",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockaccuracy,
          { "Clock accuracy",           "ptp.v2.mm.clockaccuracy",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ptp_v2_clockAccuracy_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockvariance,
          { "Clock variance",           "ptp.v2.mm.clockvariance",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_clockidentity,
          { "Clock identity",           "ptp.v2.mm.clockidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_domainNumber,
          { "domain number",           "ptp.v2.mm.domainNumber",
            FT_UINT8, BASE_DEC, NULL , 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_SO,
          { "Slave only",           "ptp.v2.mm.SlavOnly",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_stepsRemoved,
          { "steps removed",           "ptp.v2.mm.stepsRemoved",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_parentIdentity,
          { "parent ClockIdentity",           "ptp.v2.mm.parentclockidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_parentPort,
          { "parent SourcePortID",           "ptp.v2.mm.parentsourceportid",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_parentStats,
          { "parent stats",           "ptp.v2.mm.parentstats",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_observedParentOffsetScaledLogVariance,
          { "observedParentOffsetScaledLogVariance", "ptp.v2.mm.observedParentOffsetScaledLogVariance",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_observedParentClockPhaseChangeRate,
          { "observedParentClockPhaseChangeRate", "ptp.v2.mm.observedParentClockPhaseChangeRate",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_grandmasterPriority1,
          { "Grandmaster priority1", "ptp.v2.mm.grandmasterPriority1",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_grandmasterPriority2,
          { "Grandmaster priority2", "ptp.v2.mm.grandmasterPriority2",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_grandmasterclockclass,
          { "Grandmaster clock class", "ptp.v2.mm.grandmasterclockclass",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_grandmasterclockaccuracy,
          { "Grandmaster clock accuracy", "ptp.v2.mm.grandmasterclockaccuracy",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ptp_v2_clockAccuracy_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_grandmasterclockvariance,
          { "Grandmaster clock variance", "ptp.v2.mm.grandmasterclockvariance",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_grandmasterIdentity,
          { "Grandmaster clock identity", "ptp.v2.mm.grandmasterclockidentity",
            FT_UINT64, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_currentUtcOffset,
          { "CurrentUTCOffset", "ptp.v2.mm.currentutcoffset",
            FT_INT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_LI_61,
          { "leap 61", "ptp.v2.mm.li61",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_LI_59,
          { "leap 59", "ptp.v2.mm.li59",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_UTCV,
          { "CurrentUTCOffset valid", "ptp.v2.mm.CurrentUTCOffsetValid",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_PTP,
          { "PTP timescale", "ptp.v2.mm.ptptimescale",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_TTRA,
          { "Time traceable", "ptp.v2.mm.timeTraceable",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_FTRA,
          { "Frequency traceable", "ptp.v2.mm.frequencyTraceable",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_timesource,
          { "TimeSource",           "ptp.v2.mm.timesource",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &ptp_v2_timeSource_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_offset_ns,
          { "Ns",              "ptp.v2.mm.offset.ns",
            FT_INT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_offset_subns,
          { "SubNs",           "ptp.v2.mm.offset.subns",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_pathDelay_ns,
          { "Ns",           "ptp.v2.mm.pathDelay.ns",
            FT_INT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_pathDelay_subns,
          { "SubNs",           "ptp.v2.mm.pathDelay.subns",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_PortNumber,
          { "PortNumber",           "ptp.v2.mm.PortNumber",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_portState,
          { "Port state",           "ptp.v2.mm.portState",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ptp_v2_portState_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_logMinDelayReqInterval,
          { "logMinDelayReqInterval",           "ptp.v2.mm.logMinDelayReqInterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_peerMeanPathDelay_ns,
          { "Ns",           "ptp.v2.mm.peerMeanPathDelay.ns",
            FT_INT64, BASE_DEC|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_peerMeanPathDelay_subns,
          { "SubNs",           "ptp.v2.mm.peerMeanPathDelay.subns",
            FT_DOUBLE, BASE_NONE|BASE_UNIT_STRING, UNS(&units_nanosecond_nanoseconds), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_logAnnounceInterval,
          { "logAnnounceInterval",           "ptp.v2.mm.logAnnounceInterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_announceReceiptTimeout,
          { "announceReceiptTimeout",           "ptp.v2.mm.announceReceiptTimeout",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_logSyncInterval,
          { "logSyncInterval",           "ptp.v2.mm.logSyncInterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_delayMechanism,
          { "Delay mechanism",           "ptp.v2.mm.delayMechanism",
            FT_UINT8, BASE_DEC, VALS(ptp_v2_delayMechanism_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_logMinPdelayReqInterval,
          { "logMinPdelayReqInterval",           "ptp.v2.mm.logMinPdelayReqInterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_versionNumber,
          { "versionNumber",           "ptp.v2.mm.versionNumber",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_primaryDomain,
          { "Primary domain number",  "ptp.v2.mm.primaryDomain",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_faultyFlag,
          { "Faulty flag", "ptp.v2.mm.faultyFlag",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },

        { &hf_ptp_v2_mm_managementErrorId,
          { "managementErrorId",  "ptp.v2.mm.managementErrorId",
            FT_UINT16, BASE_DEC | BASE_EXT_STRING, &ptp_v2_managementErrorId_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_displayData,
          { "Display data",           "ptp.v2.mm.displayData",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_displayData_length,
          { "length",           "ptp.v2.mm.displayData.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_ucEN,
          { "Enable unicast", "ptp.v2.mm.unicastEnable",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_ptEN,
          { "Path trace unicast", "ptp.v2.mm.pathTraceEnable",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_atEN,
          { "Path trace unicast", "ptp.v2.mm.pathTraceEnable",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_keyField,
          { "Key field", "ptp.v2.mm.keyField",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_displayName,
          { "Display name",           "ptp.v2.mm.displayName",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_displayName_length,
          { "length",           "ptp.v2.mm.displayName.length",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_maxKey,
          { "Max key", "ptp.v2.mm.maxKey",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_currentOffset,
          { "Current offset", "ptp.v2.mm.currentOffset",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_jumpSeconds,
          { "Jump seconds", "ptp.v2.mm.jumpSeconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_nextjumpSeconds,
          { "Time of next jump (seconds)", "ptp.v2.mm.nextjumpSeconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_numberOfAlternateMasters,
          { "Number of alternate masters", "ptp.v2.mm.numberOfAlternateMasters",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_logAlternateMulticastSyncInterval,
          { "Alternate multicast sync interval", "ptp.v2.mm.AlternateMulticastSyncInterval",
            FT_INT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_mm_transmitAlternateMulticastSync,
          { "Transmit alternate multicast sync", "ptp.v2.mm.transmitAlternateMulticastSync",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_smpte_subtype,
          { "SMPTE SubType", "ptp.v2.oe.smpte.SubType",
            FT_UINT24, BASE_HEX, VALS(ptp_v2_org_smpte_subtype_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_data,
          { "SMPTE Data", "ptp.v2.oe.smpte.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate,
          { "defaultSystemFramerate", "ptp.v2.oe.smpte.defaultsystemframerate",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate_numerator,
          { "Numerator", "ptp.v2.oe.smpte.defaultsystemframerate.numerator",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_defaultsystemframerate_denominator,
          { "Denominator", "ptp.v2.oe.smpte.defaultsystemframerate.denominator",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_masterlockingstatus,
          { "masterLockingStatus", "ptp.v2.oe.smpte.masterlockingstatus",
            FT_UINT8, BASE_DEC, VALS(ptp_v2_org_smpte_subtype_masterlockingstatus_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags,
          { "timeAddressFlags", "ptp.v2.oe.smpte.timeaddressflags",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags_drop,
          { "Drop frame", "ptp.v2.oe.smpte.timeaddressflags.drop",
            FT_BOOLEAN, 8, TFS(&tfs_inuse_not_inuse), PTP_V2_FLAGS_OE_SMPTE_TIME_ADDRESS_FIELD_DROP,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_timeaddressflags_color,
          { "Color frame identification", "ptp.v2.oe.smpte.timeaddressflags.color",
            FT_BOOLEAN, 8, TFS(&tfs_inuse_not_inuse), PTP_V2_FLAGS_OE_SMPTE_TIME_ADDRESS_FIELD_COLOR,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_currentlocaloffset,
          { "currentLocalOffset", "ptp.v2.oe.smpte.currentlocaloffset",
            FT_INT32, BASE_DEC, NULL, 0x00,
            "Offset in seconds of Local Time from grandmaster PTP time", HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_jumpseconds,
          { "jumpSeconds", "ptp.v2.oe.smpte.jumpseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            "Size of next discontinuity, in seconds, of Local Time", HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_timeofnextjump,
          { "timeOfNextJump", "ptp.v2.oe.smpte.timeofnextjump",
            FT_UINT48, BASE_DEC, NULL, 0x00,
            "Value of the seconds portion at the time that the next discontinuity of the currentLocalOffset will occur", HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_timeofnextjam,
          { "timeOfNextJam", "ptp.v2.oe.smpte.timeofnextjam",
            FT_UINT48, BASE_DEC, NULL, 0x00,
            "Value of the seconds portion to the next scheduled Daily Jam", HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_timeofpreviousjam,
          { "timeOfPreviousJam", "ptp.v2.oe.smpte.timeofpreviousjam",
            FT_UINT48, BASE_DEC, NULL, 0x00,
            "Value of the seconds portion of the previous Daily Jam", HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_previousjamlocaloffset,
          { "previousJamLocalOffset", "ptp.v2.oe.smpte.previousjamlocaloffset",
            FT_INT32, BASE_DEC, NULL, 0x00,
            "Value of current LocalOffset at the time of the previous Daily Jam", HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving,
          { "daylightSaving", "ptp.v2.oe.smpte.daylightsaving",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_current,
          { "Current", "ptp.v2.oe.smpte.daylightsaving.current",
            FT_BOOLEAN, 8, TFS(&tfs_used_notused), PTP_V2_FLAGS_OE_SMPTE_DAYLIGHT_SAVING_CURRENT,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_next,
          { "Next", "ptp.v2.oe.smpte.daylightsaving.next",
            FT_BOOLEAN, 8, TFS(&tfs_used_notused), PTP_V2_FLAGS_OE_SMPTE_DAYLIGHT_SAVING_NEXT,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_daylightsaving_previous,
          { "Previous", "ptp.v2.oe.smpte.daylightsaving.previous",
            FT_BOOLEAN, 8, TFS(&tfs_used_notused), PTP_V2_FLAGS_OE_SMPTE_DAYLIGHT_SAVING_PREVIOUS,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_leapsecondjump,
          { "leapSecondJump", "ptp.v2.oe.smpte.leapsecondjump",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_oe_tlv_subtype_smpte_leapsecondjump_change,
          { "Change in number", "ptp.v2.oe.smpte.leapsecondjump.change",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PTP_V2_FLAGS_OE_SMPTE_LEAP_SECOND_JUMP_CHANGE,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_followup_to_sync,
          { "This is a Follow Up to Sync in Frame", "ptp.v2.analysis.followuptosync",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Which message is this a Follow Up for", HFILL }
        },
        { &hf_ptp_v2_analysis_sync_to_followup,
          { "This is a Sync to Follow Up in Frame", "ptp.v2.analysis.synctofollowup",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Which message is this a Sync for", HFILL }
        },
        { &hf_ptp_v2_analysis_pdelayreq_to_pdelayres,
          { "This is a Peer Delay Request to Response in Frame", "ptp.v2.analysis.pdelayreqtores",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Which Peer Delay Response is this a Peer Delay Request for", HFILL }
        },
        { &hf_ptp_v2_analysis_pdelayres_to_pdelayreq,
          { "This is a Peer Delay Response to Request in Frame", "ptp.v2.analysis.pdelayrestoreq",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Which Peer Delay Request is this a Peer Delay Response for", HFILL }
        },
        { &hf_ptp_v2_analysis_pdelayres_to_pdelayfup,
          { "This is a Peer Delay Response to Follow Up in Frame", "ptp.v2.analysis.pdelayfuptores",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Which Peer Delay FollowUp is this a Peer Delay Response for", HFILL }
        },
        { &hf_ptp_v2_analysis_pdelayfup_to_pdelayres,
          { "This is a Peer Delay Follow Up to Response in Frame", "ptp.v2.analysis.pdelayrestofup",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Which Peer Delay Response is this a Peer Delay FollowUp for", HFILL }
        },
        { &hf_ptp_v2_analysis_sync_timestamp,
          { "calculatedSyncTimestamp", "ptp.v2.analysis.sync.timestamp",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_sync_timestamp_seconds,
          { "calculatedSyncTimestamp (s)", "ptp.v2.analysis.sync.timestamp_seconds",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_sync_timestamp_nanoseconds,
          { "calculatedSyncTimestamp (ns)", "ptp.v2.analysis.sync.timestamp_nanoseconds",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_sync_period,
          { "measuredMessagePeriod", "ptp.v2.analysis.sync.measuredMessagePeriod",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_sync_rateRatio,
          { "calculatedSyncRateRatio", "ptp.v2.analysis.sync.calculatedRateRatio",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_sync_rateRatio_ppm,
          { "calculatedSyncRateRatio PPM", "ptp.v2.analysis.sync.calculatedRateRatio_ppm",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_pdelay_mpd_unscaled,
          { "calculatedUnscaledMeanPropagationDelay", "ptp.v2.analysis.pdelay.meanpropdelay_unscaled",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_pdelay_mpd_unscaled_seconds,
          { "calculatedUnscaledMeanPropagationDelay (s)", "ptp.v2.analysis.pdelay.meanpropdelay_unscaled_seconds",
            FT_INT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_pdelay_mpd_unscaled_nanoseconds,
          { "calculatedUnscaledMeanPropagationDelay (ns)", "ptp.v2.analysis.pdelay.meanpropdelay_unscaled_nanoseconds",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_pdelay_mpd_scaled,
          { "calculatedScaledMeanPropagationDelay", "ptp.v2.analysis.pdelay.meanpropdelay_scaled",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_pdelay_period,
          { "measuredMessagePeriod", "ptp.v2.analysis.pdelay.measuredMessagePeriod",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_pdelay_neighRateRatio,
          { "calculatedNeighborRateRatio", "ptp.v2.analysis.pdelay.calculatedNeighborRateRatio",
            FT_DOUBLE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_ptp_v2_analysis_pdelay_neighRateRatio_ppm,
          { "calculatedNeighborRateRatio PPM", "ptp.v2.analysis.pdelay.calculatedNeighborRateRatio_ppm",
            FT_INT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
    };


/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_ptp,
        &ett_ptp_flags,
        &ett_ptp_time,
        &ett_ptp_time2,
        &ett_ptp_v2,
        &ett_ptp_v2_majorsdoid,
        &ett_ptp_v2_flags,
        &ett_ptp_v2_clockidentity,
        &ett_ptp_v2_correction,
        &ett_ptp_v2_time,
        &ett_ptp_v2_time2,
        &ett_ptp_v2_managementData,
        &ett_ptp_v2_clockType,
        &ett_ptp_v2_physicalLayerProtocol,
        &ett_ptp_v2_protocolAddress,
        &ett_ptp_v2_ptptext,
        &ett_ptp_v2_faultRecord,
        &ett_ptp_v2_timeInterval,
        &ett_ptp_v2_tlv,
        &ett_ptp_v2_tlv_log_period,
        &ett_ptp_v2_sig_l1sync_flags,
        &ett_ptp_as_sig_tlv_flags,
        &ett_ptp_oe_wr_flags,
        &ett_ptp_oe_smpte_data,
        &ett_ptp_oe_smpte_framerate,
        &ett_ptp_oe_smpte_timeaddress,
        &ett_ptp_oe_smpte_daylightsaving,
        &ett_ptp_oe_smpte_leapsecondjump,
        &ett_ptp_analysis_timestamp,
        &ett_ptp_analysis_mean_propagation_delay,
    };

    static ei_register_info ei[] = {
        { &ei_ptp_v2_msg_len_too_large, { "ptp.v2.msg_len_too_large", PI_MALFORMED, PI_ERROR, "Message length goes past the end of the packet", EXPFILL }},
        { &ei_ptp_v2_msg_len_too_small, { "ptp.v2.msg_len_too_small", PI_MALFORMED, PI_ERROR, "Message length too short to include the message length field", EXPFILL }},
        { &ei_ptp_v2_sync_no_followup,  { "ptp.v2.sync_no_fup", PI_PROTOCOL, PI_WARN, "No Follow Up for this Two Step Sync", EXPFILL }},
        { &ei_ptp_v2_sync_no_fup_tlv,   { "ptp.v2.sync_no_fup_tlv", PI_PROTOCOL, PI_WARN, "No Follow Up TLV for this gPTP One Step Sync", EXPFILL }},
        { &ei_ptp_v2_followup_no_sync,  { "ptp.v2.fup_without_sync", PI_PROTOCOL, PI_WARN, "No Sync for this Follow Up", EXPFILL }},
        { &ei_ptp_v2_pdreq_no_pdresp,   { "ptp.v2.pdelay_req_without_resp", PI_PROTOCOL, PI_WARN, "No Response for this Peer Delay Request", EXPFILL }},
        { &ei_ptp_v2_pdresp_no_pdreq,   { "ptp.v2.pdelay_resp_without_req", PI_PROTOCOL, PI_WARN, "No Request for this Peer Delay Response", EXPFILL }},
        { &ei_ptp_v2_pdresp_no_pdfup,   { "ptp.v2.pdelay_resp_without_fup", PI_PROTOCOL, PI_WARN, "No Follow Up for this Peer Delay Response", EXPFILL }},
        { &ei_ptp_v2_pdresp_twostep,    { "ptp.v2.pdelay_resp_two_step_false", PI_PROTOCOL, PI_WARN, "Peer Delay Response with Two Step Flag set to false but Follow Up", EXPFILL }},
        { &ei_ptp_v2_pdfup_no_pdresp,   { "ptp.v2.pdelay_fup_without_resp", PI_PROTOCOL, PI_WARN, "No Response for this Peer Delay Follow Up", EXPFILL }},
        { &ei_ptp_v2_period_invalid,    { "ptp.v2.period.invalid", PI_PROTOCOL, PI_WARN, "Period invalid", EXPFILL }},
    };

    expert_module_t* expert_ptp;

/* Register the protocol name and description */
    proto_ptp = proto_register_protocol("Precision Time Protocol (IEEE1588)",
                                        "PTP", "ptp");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ptp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ptp = expert_register_protocol(proto_ptp);
    expert_register_field_array(expert_ptp, ei, array_length(ei));

    /* Get the decimal point based on locale */
    decimal_point = localeconv()->decimal_point;
/* Configuration */

    module_t *ptp_module = prefs_register_protocol(proto_ptp, NULL);
    prefs_register_bool_preference(ptp_module, "analyze_ptp_messages", "Analyze PTP messages",
                                   "Make the PTP dissector analyze PTP messages. Accurate Capture Timestamps required!",
                                   &ptp_analyze_messages);

/* Setup analysis data structures */
    ptp_clocks = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void
proto_reg_handoff_ptp(void)
{
    dissector_handle_t ptp_handle;
    dissector_handle_t ethertype_ptp_handle;

    ptp_handle = register_dissector("ptp", dissect_ptp, proto_ptp);
    ethertype_ptp_handle = register_dissector("ptp_over_ethernet", dissect_ptp_oE, proto_ptp);

    dissector_add_uint_range_with_preference("udp.port",  PTP_PORT_RANGE, ptp_handle);
    dissector_add_uint("ethertype", ETHERTYPE_PTP, ethertype_ptp_handle);
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

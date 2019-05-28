/**
   DIAMETER dissector

   Copyright (C) 2016-2019 Michele Campus <michelecampus5@gmail.com>

   This file is part of decoder.

   decoder is free software: you can redistribute it and/or modify it under the
   terms of the GNU General Public License as published by the Free Software
   Foundation, either version 3 of the License, or (at your option) any later
   version.

   decoder is distributed in the hope that it will be useful, but WITHOUT ANY
   WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
   A PARTICULAR PURPOSE. See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along with
   decoder. If not, see <http://www.gnu.org/licenses/>.
**/
#ifndef DIAMETER_H
#define DIAMETER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <time.h>

/* Definition of Diameter common info JSON */
#define DIAMETER_HEADER_JSON "\"diameter_info\": { [\"class\":\"%s\",\"type\":\"%s\",\"command\":\"%s\",\"app-ID\":%d] }"

/* Definition of AVPs JSON TODO */
// Basic DIAMETER

// 3GPP DIAMETER

// SIP DIAMETER

// CREDIT CONTROL
/* #define SUBSCR_ID_JSON "\"subscription-ID\":{\"Subscription-ID-data\":%s, \"Subscription-ID-type\":%u}, " */
/* #define SERV_PARAM_JSON "\"service-parameter-info\":{\"Service-parameter-type\":%u, \"Service-parameter-value\":%s}, " */
/* #define REQ_SERV_JSON "\"requested-service\":{\"Value-digits\":%lu, \"Currency-code\":%u}, " */
/* #define GRANT_SERV_JSON "\"granted-service\":{\"Value-digits\":%lu, \"Currency-code\":%u}, " */
/* #define USED_SERV_JSON "\"used-service\":{\"Value-digits\":%lu, \"Currency-code\":%u}, " */

#define JSON_BUFFER_LEN 5000

// Header Flags possibile values
/* #define REQUEST   0X80 */
/* #define PROXYABLE 0X40 */
/* #define ERROR     0X20 */
/* #define RETRASM   0X10 */

#define AVP_HDR_LEN  8
#define UNK         -1

// Flags
#define REQ          1
#define ANSW         0
// Classes
#define DIAM_BASE    0
#define _3GPP        1
#define SIP          2
#define CC           3

// Vendor-ID
#define _3GPP_ID 10415

/** ############################## COMMANDS ############################## **/

/**
   A Command Code is used to determine the action that is to be taken for a particular message.
   Each command Request/Answer pair is assigned a command code.
**/
// Diameter protocol base
typedef enum {
    AC = 271,
    AS = 274,
    CE = 257,
    DW = 280,
    DP = 282,
    RA = 258,
    ST = 275
} com_diam_base_t;

// 3GPP
typedef enum {
    // Diameter base
    UA = 300,
    SA = 301,
    LI = 302,
    MA = 303,
    RT = 304,
    PP = 305,
    UD = 306,
    PU = 307,
    SN = 308,
    PN = 309,
    BI = 310,
    MP = 311,
    // 3GPP
    UL = 316,
    CL = 317,
    AI = 318,
    ID = 319,
    DS = 320,
    PE = 321,
    NO = 323,
    EC = 324
} com_diam_3gpp_t;

// Credit control
typedef enum {
    CCC = 272
} com_diam_CC_t;

// SIP
typedef enum {
    UAS  = 283,
    SAS  = 284,
    LIS  = 285,
    MAS  = 286,
    RTS  = 287,
    PPS  = 288
} com_diam_sip_t;


/** ############################## APPLICATION-ID ############################## **/

/**
   Application-ID is used to identify for which Diameter application the message is belong to.
   The application can be an authentication application, an accounting application, or a vendor-specific application.
**/
// Diameter protocol base (establishment/teardown/maintenance)
typedef enum {
    COMMON_MSG  = 0,
    NASREQ      = 1,
    BASE_ACC    = 3,
    CREDIT_CTRL = 4,         // CREDIT CONTROL
    SIP_ID      = 6,         // SIP
    QOS         = 9,
    NAT_CA      = 12,
    ERP         = 13
    /* add more if necessary */
} diam_app_id_t;

// 3GPP protocol
typedef enum {
    _3GPP_CX    = 16777216,  // IMS I/S-CSCF to HSS interface
    _3GPP_SH    = 16777217,  // VoIP/IMS SIP Application Server to HSS interface
    _3GPP_RE    = 16777218,
    _3GPP_WX    = 16777219,
    _3GPP_ZN    = 16777220,
    _3GPP_ZH    = 16777221,
    _3GPP_GQ    = 16777222,
    _3GPP_GMB   = 16777223,
    _3GPP_GX    = 16777224,
    _3GPP_GXoGY = 16777225,
    _3GPP_MM10  = 16777226,
    _3GPP_PR    = 16777230,
    _3GPP_RX    = 16777236,  // Policy and charging control
    _3GPP_S6t   = 16777345,   // Interface between SCEF and HSS
    _3GPP_Sta   = 16777250,
    _3GPP_S6ad  = 16777251,  // LTE Roaming signaling
    _3GPP_S13   = 16777252,  // Interface between EIR and MME
    _3GPP_SLg   = 16777255   // Location services
    /* add more if necessary */
} diam_3gpp_app_id_t;


/** ############################## AVP CODES ############################## **/


/**
   AVP Codes.
   The information here is exported in Json format
**/

// Diameter protocol base
typedef enum {
    USERNAME       =   1, //
    TIMESTAMP      =  55, //
    AUTH_APP_ID    = 258, //
    VENDOR_SPEC_ID = 260, //
    SESS_ID        = 263, //
    ORIGIN_HOST    = 264, //
    VENDOR_ID      = 266, //
    RES_CODE       = 268, //
    SESS_SRV_FAIL  = 271, // not TESTED
    AUTH_REQ_TYPE  = 274, // not TESTED
    AUTH_SESS_ST   = 277, //
    ORIGIN_ST_ID   = 278, //
    DEST_REALM     = 283, //
    DEST_HOST      = 293, //
    ORIGIN_REALM   = 296  //
} avp_code_t;

// 3GPP
typedef enum {
    CHARG_ID_3GPP  =   2,
    PDP_3GPP_TYPE  =   3,
    SGSN_3GPP_IPv6 =  15,
    PKT_FILT_3GPP  =  25
} avp_code_3gpp_t;

// Credit Control
typedef enum {
    CC_CORR_ID     = 411,
    CC_INPUT       = 412,
    CC_MONEY       = 413,
    CC_OUTPUT      = 414,
    CC_REQ_NUM     = 415, // 0 - 3
    CC_REQ_TYPE    = 416, // 1 - 4
    CC_TIME        = 420,
    CC_UNIT_VAL    = 445,
    CC_CURR_CODE   = 425,
    SERV_PAR_INFO  = 440,
    SUBSCR_ID      = 443,
    VALUE_DGT      = 447,
    VALID_TIME     = 448,
    REQ_SERV_UNT   = 437,
    GRANT_SERV_UNT = 431,
    USED_SERV_UNT  = 446,
    MULTI_SERV_CC  = 456,
    SERV_CONTX_ID  = 461
} avp_code_credit_control_t;

// SIP
typedef enum {
    SIP_ACC_INFO           = 368,
    SIP_ACC_SRV_URI        = 369,
    SIP_CC_SRV_URI         = 370,
    SIP_SRV_URI            = 371,
    SIP_SRV_CPBL           = 372,
    SIP_MAN_CPBL           = 373,
    SIP_OPT_CPBL           = 374,
    SIP_SRV_TYPE           = 375,
    SIP_AUTH_DATA          = 376,
    SIP_AUTH_SCH           = 377,
    SIP_ITEM_NUM           = 378,
    SIP_AUTH               = 379,
    SIP_AUTHORIZ           = 380,
    SIP_AUTH_INFO          = 381,
    SIP_NUM_AUTH_IT        = 382,
    SIP_DEREGISTR          = 383,
    SIP_REAS_CODE          = 384,
    SIP_REAS_INFO          = 385,
    SIP_VISIT_NET_ID       = 386,
    SIP_USR_AUTH_TYPE      = 387,
    SIP_SUPP_USR_DATA_TYPE = 388,
    SIP_USR_DATA           = 389,
    SIP_USR_DATA_TYPE      = 389,
    SIP_USR_DATA_CONT      = 391,
    SIP_USR_DATA_AVAILL    = 392,
    SIP_METHOD             = 393
} avp_code_sip_t;


/** ############################################################ **/
/** ############################################################ **/
/** ############################################################ **/


/******** STRUCUTRES ********/

#define DIAM_HEADER_LEN 20
#define AVP_HEADER_LEN 8

// DIAMETER header
struct diameter_header_t
{
    u_int8_t  version;
    u_int8_t  length[3];
    u_int8_t  flags;
    u_int8_t  com_code[3];
    u_int8_t  app_id[4];
    u_int32_t hop_id;
    u_int32_t end_id;
};

#define AVP_FLAGS_P 0x20
#define AVP_FLAGS_M 0x40

// AVP header
struct avp_header_t
{
    u_int32_t code;       // 1 - 255 for RADIUS compatibility | > 255 for Diameter
    u_int8_t  flag;
    u_int8_t  length[3];  /* Values not multiple of four-octets is followed by padding to have 32-bit boundary for the next AVP (if exists) */
};

/* // CREDIT CONTROL */
/* // Requested-service-unit struct */
/* struct req_serv_unit_t */
/* { */
/*   struct avp_header_t cc_money_head;   // 413 */
/*   struct avp_header_t cc_unit_val;     // 445 */
/*   struct avp_header_t value_dgt_head;  // 447 */
/*   u_int8_t value_dgt[8]; */
/*   struct avp_header_t cc_code_head;    // 425 */
/*   u_int8_t curr_code[4]; */
/*   /\* Maybe incomplete *\/ */
/* }; */

/* // Granted-service-unit struct */
/* struct grant_serv_unit_t */
/* { */
/*   struct avp_header_t cc_money_head;   // 413 */
/*   struct avp_header_t cc_unit_val;     // 445 */
/*   struct avp_header_t value_dgt_head;  // 447 */
/*   u_int8_t value_dgt[8]; */
/*   struct avp_header_t cc_code_head;    // 425 */
/*   u_int8_t curr_code[4]; */
/*   /\* Maybe incomplete *\/ */
/* }; */

/* // Used-service-unit struct */
/* struct used_serv_unit_t */
/* { */
/*   struct avp_header_t cc_money_head;   // 413 */
/*   struct avp_header_t cc_unit_val;     // 445 */
/*   struct avp_header_t value_dgt_head;  // 447 */
/*   u_int8_t value_dgt[8]; */
/*   struct avp_header_t cc_code_head;    // 425 */
/*   u_int8_t curr_code[4]; */
/*   /\* Maybe incomplete *\/ */
/* }; */
/* /\******** *************** ********\/ */

/* List of ALL the structures for the AVP information block TODO: moved to .c*/
/* char* serv_contx_id;                       // 461 */
/* u_int32_t cc_req_num;                      // 415 */
/* u_int32_t cc_req_type;                     // 416 (1 - 4) */
/* u_int32_t org_state_id;                    // 278 */
/* u_int32_t valid_time;                      // 448 */
/* struct req_serv_unit_t *req_serv_unit;     // 437 */
/* struct grant_serv_unit_t *grant_serv_unit; // 431 */
/* struct used_serv_unit_t *used_serv_unit;   // 446 */
/* /\*** TODO finish to add fields here ***\/ */

/******** *************** ********/

#endif

/**
   DIAMETER dissector

   Copyright (C) 2016-2021 Michele Campus <michelecampus5@gmail.com>

   Based on code from https://github.com/moonlight-stream/moonlight-common-c/blob/master/src/RtspParser.c

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
#ifndef PARSER_DIAMETER_H
#define PARSER_DIAMETER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <time.h>

#define DIAMETER_PROTO_TYPE 0x38
/* Definition of Diameter common info JSON */
#define DIAMETER_HEADER_JSON "{\"type\":\"%s\",\"command\":%d,\"app-ID\":%u,\"hop-by-hop-ID\":\"%s\",\"end-to-end-ID\":\"%s\","
#define JSON_BUFFER_LEN 5000

// Header Flags possibile values
/* #define REQUEST   0X80 */
/* #define PROXYABLE 0X40 */
/* #define ERROR     0X20 */
/* #define RETRASM   0X10 */

#define AVP_HDR_LEN  8
// Flag Type
#define ANSW         0
#define REQ          1
#define ANSW_PRX     2
#define REQ_PRX      3
#define PRX          4
// Vendor-ID
#define _3GPP_ID 10415

// CORRELATION IDs
// Cx - Dx - Rx
#define SESS_ID_CORR      1
#define PUB_ID_CORR       2
#define COUNTRY_CODE_CORR 3
// add define here for others


/** ############################## APPLICATION-ID ############################## **/

/**
   Application-ID is used to identify for which Diameter application the message is belong to.
   The application can be an authentication application, an accounting application, or a vendor-specific application.
**/
// Diameter protocol base (establishment/teardown/maintenance)
#define  COMMON_MSG   0
#define  NASREQ       1
#define  MOBILE_IPv4  2
#define  BASE_ACC     3
#define  CREDIT_CTRL  4
#define  EAP          5
#define  SIP_ID       6
#define  MIP6I        7
#define  MIP6A        8 
#define  QOS          9
#define  CUPD         10
#define  IKESK        11
#define  NAT_CA       12
#define  ERP          13
// add more here if needed

// 3GPP protocol
#define    _3GPP_CX    16777216  // IMS I/S-CSCF to HSS interface
#define    _3GPP_SH    16777217  // VoIP/IMS SIP Application Server to HSS interface
#define    _3GPP_RE    16777218
#define    _3GPP_WX    16777219
#define    _3GPP_ZN    16777220
#define    _3GPP_ZH    16777221
#define    _3GPP_GQ    16777222
#define    _3GPP_GMB   16777223
#define    _3GPP_GX    16777224
#define    _3GPP_GXoGY 16777225
#define    _3GPP_MM10  16777226
#define    _3GPP_PR    16777230
#define    _3GPP_RX    16777236  // Policy and charging control
#define    _3GPP_S6t   16777345  // Interface between SCEF and HSS
#define    _3GPP_Sta   16777250
#define    _3GPP_S6ad  16777251  // LTE Roaming signaling
#define    _3GPP_S13   16777252  // Interface between EIR and MME
#define    _3GPP_SLg   16777255  // Location services
// add more here if needed


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
    SESS_SRV_FAIL  = 271, //
    AUTH_REQ_TYPE  = 274, //
    AUTH_SESS_ST   = 277, //
    ORIGIN_ST_ID   = 278, //
    DEST_REALM     = 283, //
    DEST_HOST      = 293, //
    ORIGIN_REALM   = 296, //
    EXP_RES        = 297, //
    EXP_RES_CODE   = 298  //
} avp_code_t;

// 3GPP
typedef enum {
    CHARG_ID_3GPP    =   2,
    PDP_3GPP_TYPE    =   3,
    SGSN_3GPP_IPv6   =  15,
    PKT_FILT_3GPP    =  25,
    /* Note: The AVP codes from 1 to 255 are reserved for backwards compatibility
       with 3GPP RADIUS Vendor Specific Attributes */
    MEDIA_COMP_DESCR = 517,
    VISIT_NET_ID     = 600,
    PUB_ID           = 601,
    SERVER_NAME      = 602,
    USER_DATA        = 606,
    IP_CAN_TYPE      = 1027,
    RAT_TYPE         = 1032
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
    SUBSCR_ID_DATA = 444,
    SUBSCR_ID_TYPE = 450,
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
    u_int32_t app_id;
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

/**
   Functions for the dissection
   @return JSON length + correlation-id
**/
// Parse packet, check if it's Diameter and create JSON buffer with protocol information
int diameter_parser(const unsigned char *packet, int size_payload, char *json_buffer, int buffer_len);

#endif

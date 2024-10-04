/**
   DIAMETER dissector

   Copyright (C) 2016-2024 Michele Campus <michelecampus5@gmail.com>

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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "diameter.h"

// Macro to check if the k-th bit is set (1) or not (0)
#define CHECK_BIT(var, k) ((var) & (1<<(k-1)))

#define APP_UNK "APP ID unknown"

/* List of ALL the structures for the AVP information block */
static char *session_id;
static char *auth_sess_st;
static char *auth_req_type;
static char *org_host;
static char *dst_host;
static char *org_realm;
static char *dst_realm;
static char *sess_fail_type;
static char *pub_id;
static char *visit_net_id;
static char *srv_name;
static char *username_id;
static char *user_data;
static u_int32_t auth_app_id;
static u_int32_t vend_id;
static u_int32_t res_code;
static u_int32_t orgst_id;
static u_int32_t exp_res_code;
static u_int32_t subscr_id_type;
static u_int32_t country_code;
static u_int32_t ip_can_type;
static u_int32_t rat_type;
char buff_tm[30] = {0};

/**
   Swap endian value of passed variable
   @param  number to be change
   @return number after endian swap
**/
static u_int32_t swap_endian(u_int32_t num)
{
    // Swap endian (big to little) or (little to big)
    uint32_t z0, z1, z2, z3;
    uint32_t res;

    z0 = (num & 0x000000ff) << 24;
    z1 = (num & 0x0000ff00) << 8;
    z2 = (num & 0x00ff0000) >> 8;
    z3 = (num & 0xff000000) >> 24;
    res = z0 | z1 | z2 | z3;

    return res;
}

/* static char *get_common_appID_string(u_int32_t app_id) */
/* { */
/*     switch(app_id) { */
/*       case COMMON_MSG:  return "Diameter Common Msg"; */
/*       case NASREQ:      return "NASREQ"; */
/*       case MOBILE_IPv4: return "Mobile IPv4"; */
/*       case BASE_ACC:    return "Diameter Base Accounting"; */
/*       case CREDIT_CTRL: return "Diameter Credit Control"; */
/*       case EAP:         return "Diameter EAP"; */
/*       case SIP_ID:      return "Diameter SIP App"; */
/*       case MIP6I:       return "Diameter Mobile IPv6 IKE"; */
/*       case MIP6A:       return "Diameter Mobile IPv6 Auth"; */
/*       case QOS:         return "Diameter QOS"; */
/*       case CUPD:        return "Diameter Capabilities Update"; */
/*       case IKESK:       return "Diameter IKE SK"; */
/*       case NAT_CA:      return "Diameter NAT Control Application"; */
/*       case ERP:         return "Diameter ERP"; */
/*       default:          return NULL; */
/*     } */
/* } */
/* static char *get_3gpp_appID_string(u_int32_t app_id) */
/* { */
/*     switch(app_id) { */
/*     case _3GPP_CX: return "3GPP CX"; */
/*     case _3GPP_SH: return "3GPP SH"; */
/*     case _3GPP_RX: return "3GPP RX"; */
/*     case _3GPP_GX: return "3GPP GX"; */
/*         // TODO finish the list */
/*     default: return NULL; */
/*     } */
/* } */


/**
   Parse packet and fill JSON buffer
   @param  packet, size_payload, json_buffer, buffer_len
   @return 0 if pkt is diameter and JSON buffer is created
   @return -1 in case of errors
**/
int diameter_parser(const unsigned char *packet, int size_payload, char *json_buffer, int buffer_len)
{
    char type[20] = {0};
    char hop_by_hop_str[20] = {0};
    char end_to_end_str[20] = {0};
    /* char *app_id_str = NULL; */
    int offset = 0, js_ret = 0;
    u_int32_t app_id;
    u_int32_t hop_by_hop_id;
    u_int32_t end_to_end_id;
    u_int16_t command;
    u_int8_t  flag;

    // check param
    if(!packet || size_payload == 0) {
        fprintf(stderr, "::Error:: parameters not valid\n");
        return -1;
    }

    // cast to diameter header
    struct diameter_header_t *diameter = (struct diameter_header_t *) packet;

    // check if the VERSION is correct
    if(diameter->version != 0x01) {
        fprintf(stderr, "::Error:: Wrong version for Diameter protocol");
        return -1;
    }

     /* TYPE => check if Flag bit R is set to 0-1-2-3 (Answer-Request-Request/Proxyable-Proxyable) */
    flag = CHECK_BIT(diameter->flags, 8);
    if(flag == 0) { // Answer
        flag = CHECK_BIT(diameter->flags, 7);
        if(flag == 0) {
            snprintf(type, (strlen("Answer")+1), "Answer");
        } else {
            snprintf(type, (strlen("Answer-Proxyable")+1), "Answer-Proxyable");
        }
    } else { // Request
        flag = CHECK_BIT(diameter->flags, 7);
        if(flag == 0) {
            snprintf(type, (strlen("Request")+1), "Request");
        } else {
            snprintf(type, (strlen("Request-Proxyable")+1), "Request-Proxyable");
        }
    }

    /* COMMAND */
    command = diameter->com_code[2] + (diameter->com_code[1] << 8) + (diameter->com_code[0] << 8);

    /* APPLICATION-ID */
    app_id = diameter->app_id;
    app_id = swap_endian(app_id);
    /* app_id_str = get_common_appID_string(app_id); */
    /* if(app_id_str == NULL) */
    /*     app_id_str = get_3gpp_appID_string(app_id); */
    /* if(app_id_str == NULL) */
    /*     app_id_str = APP_UNK; */

    /* HOP-BY-HOP */
    hop_by_hop_id = diameter->hop_id;
    hop_by_hop_id = swap_endian(hop_by_hop_id);
    sprintf(hop_by_hop_str, "%x", hop_by_hop_id);

    /* END-TO-END */
    end_to_end_id = diameter->end_id;
    end_to_end_id = swap_endian(end_to_end_id);
    sprintf(end_to_end_str, "%x", end_to_end_id);


    /*** CREATE JSON BUFFER ***/
    js_ret += snprintf(json_buffer, buffer_len,
                       DIAMETER_HEADER_JSON, type, command, app_id, hop_by_hop_str, end_to_end_str);

    /***** END of parsing Diamter Header *****/


    // Calculate the length of payload from header field
    u_int16_t length = diameter->length[2] + (diameter->length[1] << 8) + (diameter->length[0] << 8);

    if(length != size_payload) {
        fprintf(stderr, "::Error:: Diameter length is not equal to size payload\n");
        return -1;
    }

    // set "start" and "end" pointer to begin and end of the payload pkt
    const unsigned char *start = packet;
    const unsigned char *end = packet + (length-1);

    // move to AVPs
    start = start + DIAM_HEADER_LEN;

    // increment offset
    offset += DIAM_HEADER_LEN;

    /**
       Create json buffer
    **/
    js_ret += snprintf((json_buffer + js_ret), buffer_len, "\"payload\":{ ");

    while(start < end && offset < length) {

        // Info from AVP headers
        u_int32_t avp_code;
        u_int16_t avp_len;
        u_int16_t l;
        u_int32_t _vendor_id = 0;
        u_int8_t  padd = 0;
        u_int32_t unk = 0;

        // Header AVP
        struct avp_header_t *avp = (struct avp_header_t *) start;

        // calculate AVP code
        avp_code = ntohl(avp->code);

        // calculate AVP length
        avp_len = avp->length[2] + (avp->length[1] << 8) + (avp->length[0] << 8);

        // move pointer forward and increase the offset
        start += AVP_HDR_LEN;
        offset += AVP_HDR_LEN;
        unk += AVP_HDR_LEN;

        // check AVP flag - search the presence of Vendor-ID field (4 bytes optional)
        if(CHECK_BIT(avp->flag, 8) == 128) {
            /* vendor_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8); */
            /* // put buffer in JSON buffer */
            /* js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
            /*                    "\"vendor-ID\":%u, ", vendor_id); */
            start += 4;
            offset += 4;
            unk += 4;
            _vendor_id = 4;
        }

        switch(avp_code) {

        case SESS_ID: {

            u_int16_t sess_id_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            session_id = calloc(sess_id_len+1, sizeof(char));
            memcpy(session_id, start, sess_id_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }
            start += (sess_id_len + padd);   // move pointer forward
            offset += (sess_id_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"session-id\":\"%s\", ", session_id);
            // free
            if(session_id)
                free(session_id);
            break;
        }

        case VENDOR_SPEC_ID: { // Grouped

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            break;
        }

        case AUTH_SESS_ST: {

            u_int16_t auth_sess_len = avp_len - AVP_HEADER_LEN - _vendor_id;

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            auth_sess_st = calloc(strlen("NO-STATE-MAINTAINED")+1, sizeof(char));

            int auth_val = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            if(auth_val == 1) snprintf(auth_sess_st, strlen("NO-STATE-MAINTAINED")+1, "NO-STATE-MAINTAINED");
            else if(auth_val == 0) snprintf(auth_sess_st, strlen("STATE-MAINTAINED")+1, "STATE-MAINTAINED");

            start += (auth_sess_len + padd);   // move pointer forward
            offset += (auth_sess_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"auth-sess-st\":\"%s\", ", auth_sess_st);
            // free
            if(auth_sess_st)
                free(auth_sess_st);

            break;
        }

        case AUTH_REQ_TYPE: {

            u_int16_t auth_req_len = avp_len - AVP_HEADER_LEN - _vendor_id;

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            auth_req_type = calloc(strlen("AUTHORIZE_AUTHENTICATE")+1, sizeof(char));

            int auth_req_val = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            if(auth_req_val == 1) snprintf(auth_req_type, strlen("AUTHENTICATE_ONLY")+1, "AUTHENTICATE_ONLY");
            else if(auth_req_val == 2) snprintf(auth_sess_st, strlen("AUTHORIZE_ONLY")+1, "AUTHORIZE_ONLY");
            else if(auth_req_val == 3) snprintf(auth_sess_st, strlen("AUTHORIZE_AUTHENTICATE")+1, "AUTHORIZE_AUTHENTICATE");

            start += (auth_req_len + padd);   // move pointer forward
            offset += (auth_req_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"auth-req-type\":\"%s\", ", auth_req_type);
            // free
            if(auth_req_type)
                free(auth_req_type);
            break;
        }

        case SESS_SRV_FAIL: {

            u_int16_t sess_fail_len = avp_len - AVP_HEADER_LEN - _vendor_id;

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            sess_fail_type = calloc(strlen("TRY_AGAIN_ALLOW_SERVICE")+1, sizeof(char));

            int sess_fail_val = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            if(sess_fail_val == 0) snprintf(sess_fail_type, strlen("REFUSE_SERVICE")+1, "REFUSE_SERVICE");
            else if(sess_fail_val == 1) snprintf(sess_fail_type, strlen("TRY_AGAIN")+1, "TRY_AGAIN");
            else if(sess_fail_val == 2) snprintf(sess_fail_type, strlen("ALLOW_SERVICE")+1, "ALLOW_SERVICE");
            else if(sess_fail_val == 3) snprintf(sess_fail_type, strlen("TRY_AGAIN_ALLOW_SERVICE")+1, "TRY_AGAIN_ALLOW_SERVICE");

            start += (sess_fail_len + padd);   // move pointer forward
            offset += (sess_fail_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"sess-server-failover\":\"%s\", ", sess_fail_type);
            // free
            if(sess_fail_type)
                free(sess_fail_type);
            break;
        }

        case ORIGIN_HOST: {

            u_int16_t org_host_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            org_host = calloc(org_host_len+1, sizeof(char));
            memcpy(org_host, start, org_host_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (org_host_len + padd);   // move pointer forward
            offset += (org_host_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"origin-host\":\"%s\", ", org_host);
            // free
            if(org_host)
                free(org_host);
            break;
        }

        case DEST_HOST: {

            u_int16_t dst_host_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            dst_host = calloc(dst_host_len+1, sizeof(char));
            memcpy(dst_host, start, dst_host_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (dst_host_len + padd);   // move pointer forward
            offset += (dst_host_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"destination-host\":\"%s\", ", dst_host);
            // free
            if(dst_host)
                free(dst_host);
            break;
        }

        case ORIGIN_REALM: {

            u_int16_t org_realm_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            org_realm = calloc(org_realm_len+1, sizeof(char));
            memcpy(org_realm, start, org_realm_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (org_realm_len + padd);   // move pointer forward
            offset += (org_realm_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"origin-realm\":\"%s\", ", org_realm);
            // free
            if(org_realm)
                free(org_realm);
            break;
        }

        case DEST_REALM: {

            u_int16_t dst_realm_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            dst_realm = calloc(dst_realm_len+1, sizeof(char));
            memcpy(dst_realm, start, dst_realm_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (dst_realm_len + padd);   // move pointer forward
            offset += (dst_realm_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"destination-realm\":\"%s\", ", dst_realm);
            // free
            if(dst_realm)
                free(dst_realm);
            break;
        }

        case AUTH_APP_ID: {

            u_int16_t auth_app_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            auth_app_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            auth_app_id = swap_endian(auth_app_id);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (auth_app_len + padd);   // move pointer forward
            offset += (auth_app_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"auth-app-ID\":%x, ", auth_app_id);
            break;
        }

        case VENDOR_ID: {

            u_int16_t vend_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            vend_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (vend_len + padd);   // move pointer forward
            offset += (vend_len + padd);  // update offset

            // put buffer in JSON buffer
            if(vend_id == _3GPP_ID)
                js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                                   "\"vendor-ID\":\"%s\", ", "3GPP");
            else
                js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                                   "\"vendor-ID\":\"%s\", ", "Others");
            break;
        }

        case RES_CODE: {

            char rc_buff[50] = {0};
            u_int16_t res_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            res_code = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (res_len + padd);   // move pointer forward
            offset += (res_len + padd);  // update offset

            if(res_code >= 1000 && res_code < 2000) strncpy(rc_buff, "Informational", sizeof(rc_buff));
            else if(res_code >= 2000 && res_code < 3000) strncpy(rc_buff, "Success", sizeof(rc_buff));
            else if(res_code >= 3000 && res_code < 4000) strncpy(rc_buff, "Protocol Errors", sizeof(rc_buff));
            else if(res_code >= 4000 && res_code < 5000) strncpy(rc_buff, "Transient Failures", sizeof(rc_buff));
            else if(res_code >= 5000 && res_code < 6000) strncpy(rc_buff, "Permanent Failure", sizeof(rc_buff));

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"res-code\":\"%s\", ", rc_buff);
            break;
        }

        case ORIGIN_ST_ID: {

            u_int16_t orgst_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            orgst_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (orgst_len + padd);   // move pointer forward
            offset += (orgst_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"origin-state-id\":%u, ", orgst_id);
            break;
        }

        case TIMESTAMP: {

            u_int16_t time_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            /* memset(buff_tm, 0, time_len); */
            /* memcpy(buff_tm, start, time_len+1); */
            time_t tm = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8); /* CHECK */
            sprintf(buff_tm, "%s", ctime(&tm));
            u_int8_t pos = strlen(buff_tm) - 1;
            buff_tm[pos] = '\0';

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (time_len + padd);  // move pointer forward
            offset += (time_len + padd); // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"event-timestamp\":\"%s\", ", buff_tm);
            break;
        }

        case EXP_RES: { // Grouped

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            break;
        }

        case EXP_RES_CODE: {

            u_int16_t exp_res_code_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            exp_res_code = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (exp_res_code_len + padd);   // move pointer forward
            offset += (exp_res_code_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"exp-result-code\":%u, ", exp_res_code);
            break;
        }

            // 3GPP
        case PUB_ID: {

            u_int16_t pub_id_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            pub_id = calloc(pub_id_len+1, sizeof(char));
            memcpy(pub_id, start, pub_id_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (pub_id_len + padd);   // move pointer forward
            offset += (pub_id_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"public-identity\":\"%s\", ", pub_id);
            // free
            if(pub_id)
                free(pub_id);
            break;
        }

        case SUBSCR_ID: { // Grouped

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            break;
        }

        case SUBSCR_ID_TYPE: {
            u_int16_t subscr_id_type_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            subscr_id_type = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (subscr_id_type_len + padd);   // move pointer forward
            offset += (subscr_id_type_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"subscr-id-type\":%u, ", subscr_id_type);
            break;
        }

        case SUBSCR_ID_DATA: {
            char subscr_id_data[50] = {0};
            char cc[3] = {0};
            u_int16_t subscr_id_data_len = avp_len - AVP_HEADER_LEN - _vendor_id;

            memcpy(subscr_id_data, start, subscr_id_data_len);
            memcpy(cc, subscr_id_data, 2);
            country_code = atoi(cc);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (subscr_id_data_len + padd);   // move pointer forward
            offset += (subscr_id_data_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"country-code\":%u, ", country_code);
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"subscr-id\":\"%s\", ", subscr_id_data);
            break;

        }

        case VISIT_NET_ID: {

            u_int16_t visit_net_id_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            visit_net_id = calloc(visit_net_id_len+1, sizeof(char));
            memcpy(visit_net_id, start, visit_net_id_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (visit_net_id_len + padd);   // move pointer forward
            offset += (visit_net_id_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"visit-network-id\":\"%s\", ", visit_net_id);
            // free
            if(visit_net_id)
                free(visit_net_id);
            break;
        }

        case SERVER_NAME: {

            u_int16_t srv_name_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            srv_name = calloc(srv_name_len+1, sizeof(char));
            memcpy(srv_name, start, srv_name_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (srv_name_len + padd);   // move pointer forward
            offset += (srv_name_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"server-name\":\"%s\", ", srv_name);
            // free
            if(srv_name)
                free(srv_name);
            break;
        }

        case USERNAME: {

            u_int16_t username_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            username_id = calloc(username_len+1, sizeof(char));
            memcpy(username_id, start, username_len);

            start += (username_len + padd);   // move pointer forward
            offset += (username_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"user-name\":\%s\", ", username_id);
            // free
            if(username_id)
                free(username_id);
            break;
        }

        case USER_DATA: {

            u_int16_t user_data_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            user_data = calloc(user_data_len+1, sizeof(char));
            memcpy(user_data, start, user_data_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (user_data_len + padd);   // move pointer forward
            offset += (user_data_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"user-data\":\"%s\", ", user_data);
            // free
            if(user_data)
                free(user_data);
            break;
        }

        case IP_CAN_TYPE: {
            u_int16_t ip_can_type_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            ip_can_type = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (ip_can_type_len + padd);   // move pointer forward
            offset += (ip_can_type_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"ip-can-type\":%u, ", ip_can_type);
            break;
        }

        case RAT_TYPE: {
            u_int16_t rat_type_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            rat_type = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (rat_type_len + padd);   // move pointer forward
            offset += (rat_type_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"rat-type\":%u, ", rat_type);
            break;
        }

        case MEDIA_COMP_DESCR: {
            // TODO
        }

        default: {

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (avp_len - unk + padd);
            offset += (avp_len - unk + padd);
        }
        } // switch
    }

    js_ret += snprintf((json_buffer + js_ret - 2), 3, "%s", "}}");
    js_ret -= 2;

    return js_ret; // OK
}

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
#include "diameter.h"

// Macro to check if the k-th bit is set (1) or not (0)
#define CHECK_BIT(var, k) ((var) & (1<<(k-1)))

/* Array of string definition for commands (used for convertion from enum to string) */
static const char *com_diam_base_arr[] = { "AC", "AS", "CE", "DW", "DP", "RA", "ST" };
static const char *com_diam_3gpp_arr[] = { "UA", "SA", "LI", "MA", "RT", "PP", "UD", "PU", "SN", "PN", "BI", "MP", "UL", "CL", "AI", "ID", "DS", "PE", "NO", "EC" };
static const char *com_diam_CC_arr[]   = { "CC" };
static const char *com_diam_sip_arr[]  = { "UA", "SA", "LI", "MA", "RT", "PP" };

/* List of ALL the structures for the AVP information block */
static char *username_id;
static char *session_id;
static char *vendor_spec_id;
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
static char *user_data;
static char *exp_res;
static u_int32_t auth_app_id;
static u_int32_t vend_id;
static u_int32_t res_code;
static u_int32_t orgst_id;
static u_int32_t exp_res_code;
char buff_tm[30] = {0};

/* static inline CHECK_BIT(var, k) { */
/*     int i = ((var) & (1<<(k-1))); */
/*     return i; */
/* } */

/**
   Swap endian value of passed variable
   @param  number to be change
   @return number after endian swap
**/
static u_int32_t swap_endian(u_int32_t num) {

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

/**
   check if the passed variable is a diameter command
   @param  command code to check
   @return the num >= 0 associated to class of command (Base, 3GPP, SIP, CC) and #com_string associated to com_code
   @return -1 in case of invalid command
**/
static int check_command(u_int16_t com_code, const char* com_string) {

    int i, j;

    // check for CC command
    if(com_code == CCC) {
        snprintf(com_string, 3, "CC");
        return CC;
    }
    // check for DIAM_BASE command
    switch(com_code) {
      case CE: {
          snprintf(com_string, 3, "%s", com_diam_base_arr[0]);
          return DIAM_BASE;
      }
      case RA: {
          snprintf(com_string, 3, "%s", com_diam_base_arr[1]);
          return DIAM_BASE;
      }
      case AC: {
          snprintf(com_string, 3, "%s", com_diam_base_arr[2]);
          return DIAM_BASE;
      }
      case AS: {
          snprintf(com_string, 3, "%s", com_diam_base_arr[3]);
          return DIAM_BASE;
      }
      case ST: {
          snprintf(com_string, 3, "%s", com_diam_base_arr[4]);
          return DIAM_BASE;
      }
      case DW: {
          snprintf(com_string, 3, "%s", com_diam_base_arr[5]);
          return DIAM_BASE;
      }
      case DP: {
          snprintf(com_string, 3, "%s", com_diam_base_arr[6]);
          return DIAM_BASE;
      }
    }

    // check for 3GPP command
    for (i = UA, j = 0; i <= EC; i++, j++) {
        if(i == com_code) {
            /* printf("string = %s\n", com_diam_base_arr[j]); */
            if(i <= MP)
                snprintf(com_string, 3, "%s", com_diam_3gpp_arr[j]);
            else
                snprintf(com_string, 3, "%s", com_diam_3gpp_arr[j-4]);
            return _3GPP;
        }
    }
    // check for SIP command
    for (i = UAS, j = 0; i <= PPS; i++, j++) {
        if(i == com_code) {
            snprintf(com_string, 3, "%s", com_diam_sip_arr[j]);
            return SIP;
        }
    }

    return -1;
}

/**
   check if the passed variable is a diameter application ID
   @param  application ID to check
   @return the num >= 0 associated to class of command (Base, 3GPP, SIP, CC)
   @return -1 in case of invalid command
**/
static int check_appID(u_int32_t app_id) {

    int i;

    // check for CREDIT_CTRL app ID
    if(app_id == CREDIT_CTRL) return CC;
    // check for SIP command
    if(app_id == SIP_ID) return SIP;
    // check for DIAM_BASE command
    for (i = COMMON_MSG; i <= ERP; i++)
        if(i == app_id)
            return DIAM_BASE;
    // check for 3GPP command
    for (i = _3GPP_CX; i <= _3GPP_SLg; i++)
        if(i == app_id)
            return _3GPP;

    return -1;
}


/**
   Parse packet and fill JSON buffer
   @param  packet, size_payload, json_buffer, buffer_len
   @return 0 if pkt is diameter and JSON buffer is created
   @return -1 in case of errors
**/
int diameter_parser(const u_char *packet, int size_payload, char *json_buffer, int buffer_len)
{
    int offset = 0, js_ret = 0;
    // header field var for JSON
    int classCom = -1, classApp = -1;
    u_int8_t flag;
    u_int16_t command;
    u_int32_t app_id;
    char type[20] = {0};
    char class[20] = {0};
    // string for JSON command and app IDs
    const char com_string[8] = {0};
    const char app_string[8] = {0};


    // check param
    if(!packet || size_payload == 0) {
        fprintf(stderr, "::Error:: parameters not valid\n");
        return -1;
    }

    // cast to diameter header
    struct diameter_header_t *diameter = (struct diameter_header_t *) packet;

    // check if the version is correct
    if(diameter->version != 0x01) {
        fprintf(stderr, "::Error:: Wrong version for Diameter protocol\n");
        return -1;
    }

    // check if Flag bit R is set to 0 or 1 (Answer or Request)
    flag = (CHECK_BIT(diameter->flags, 8)) ? REQ : ANSW;
    if(flag != REQ && flag != ANSW) {
        fprintf(stderr, "::Error:: Wrong flags value for Diameter protocol\n");
        return -1;
    }

    // check if the Command is correct
    command = diameter->com_code[2] + (diameter->com_code[1] << 8) + (diameter->com_code[0] << 8);
    /* printf("command = %u\n", command); */
    classCom = check_command(command, &com_string);
    if(classCom == UNK) {
        fprintf(stderr, "::Warning:: Command unknown for Diameter protocol\n");
        snprintf(com_string, (strlen("Unknown")+1), "Unknown");
    }

    // check if Applicaption ID is correct
    /* app_id = diameter->app_id[3] + (diameter->app_id[2] << 8) + (diameter->app_id[1] << 8) + (diameter->app_id[0] << 8); */
    app_id = diameter->app_id;
    app_id = swap_endian(app_id);
    classApp = check_appID(app_id);
    if(classApp == UNK) {
        fprintf(stderr, "::Warning:: Command unknown for Diameter protocol\n");
        app_id = UNK;
    }

    /* check for the Class */
    if(classCom != classApp) {
        fprintf(stderr, "::Warning:: Class is different in Command and Application ID. ");
        fprintf(stderr, "Command or Application ID is unknown\n\n");
        /* return -1; */
    }

    // From int to string
    if(flag == REQ) snprintf(type, (strlen("Request")+1), "Request");
    else snprintf(type, (strlen("Answer")+1), "Answer");
    if(classCom == DIAM_BASE) snprintf(class, (strlen("Diameter")+1), "Diameter");
    else if(classCom == _3GPP) snprintf(class, (strlen("3GPP")+1), "3GPP");
    else if(classCom == SIP) snprintf(class, (strlen("SIP")+1), "SIP");
    else if(classCom == CC) snprintf(class, (strlen("Credit Control")+1), "Credit Control");
    else snprintf(class, (strlen("Unknown")+1), "Unknown");

    // Write correct string values for diameter header



    /*** CREATE JSON BUFFER ***/
    js_ret += snprintf(json_buffer, buffer_len,
                       DIAMETER_HEADER_JSON, class, type, com_string, app_id);


    // Calculate the length of payload from header field
    u_int16_t length = diameter->length[2] + (diameter->length[1] << 8) + (diameter->length[0] << 8);

    if(length != size_payload) {
        fprintf(stderr, "::Error:: Diameter length is not equal to size payload\n");
        return -1;
    }

    // set "start" and "end" pointer to begin and end of the payload pkt
    const u_char *start = packet;
    const u_char *end = packet + (length-1);

    // move to AVPs
    start = start + DIAM_HEADER_LEN;

    // increment offset
    offset += DIAM_HEADER_LEN;

    /**
       Create json buffer
    **/
    /* js_ret += snprintf((json_buffer + js_ret), buffer_len, "{ \"diameter_report_information\":{ "); */

    while(start < end && offset < length) {

        // Info from AVP headers
        u_int32_t avp_code;
        u_int8_t  flag;
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

        // check for padding
        l = avp_len;
        while(l % 4 != 0) {
            padd++; l++;
        }
        
        // move pointer forward and increase the offset
        start += AVP_HDR_LEN;
        offset += AVP_HDR_LEN;
        unk += AVP_HDR_LEN;

        // check AVP flag - search the presence of Vendor-ID field (4 bytes optional)
        if(CHECK_BIT(avp->flag, 8) == 128) {
            start += 4;
            offset += 4;
            unk += 4;
            _vendor_id = 4;
        }

        switch(avp_code) {

        case USERNAME: {

            u_int16_t username_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            username_id = calloc(username_len, sizeof(char));
            memcpy(username_id, start, username_len);

            start += (username_len + padd);   // move pointer forward
            offset += (username_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"user-name\":%s,", username_id);
            break;
        }

        case SESS_ID: {

            u_int16_t sess_id_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            session_id = calloc(sess_id_len, sizeof(char));
            memcpy(session_id, start, sess_id_len);

            start += (sess_id_len + padd);   // move pointer forward
            offset += (sess_id_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"session-ID\":%s,", session_id);
            break;
        }

        case VENDOR_SPEC_ID: { // Grouped

            u_int16_t vend_spec_id_len = avp_len - AVP_HEADER_LEN - _vendor_id;

            break;
        }

        case AUTH_SESS_ST: {

            u_int16_t auth_sess_len = avp_len - AVP_HEADER_LEN - _vendor_id;

            auth_sess_st = calloc(strlen("NO-STATE-MAINTAINED")+1, sizeof(char));

            int auth_val = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            if(auth_val == 1) snprintf(auth_sess_st, strlen("NO-STATE-MAINTAINED")+1, "NO-STATE-MAINTAINED");
            else if(auth_val == 0) snprintf(auth_sess_st, strlen("STATE-MAINTAINED")+1, "STATE-MAINTAINED");

            start += (auth_sess_len + padd);   // move pointer forward
            offset += (auth_sess_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"auth-sess-st\":%s,", auth_sess_st);
            break;
        }

        case AUTH_REQ_TYPE: {

            u_int16_t auth_req_len = avp_len - AVP_HEADER_LEN - _vendor_id;

            auth_req_type = calloc(strlen("AUTHORIZE_AUTHENTICATE")+1, sizeof(char));

            int auth_req_val = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            if(auth_req_val == 1) snprintf(auth_req_type, strlen("AUTHENTICATE_ONLY")+1, "AUTHENTICATE_ONLY");
            else if(auth_req_val == 2) snprintf(auth_sess_st, strlen("AUTHORIZE_ONLY")+1, "AUTHORIZE_ONLY");
            else if(auth_req_val == 3) snprintf(auth_sess_st, strlen("AUTHORIZE_AUTHENTICATE")+1, "AUTHORIZE_AUTHENTICATE");

            start += (auth_req_len + padd);   // move pointer forward
            offset += (auth_req_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"auth-req-type\":%s,", auth_req_type);
            break;
        }

        case SESS_SRV_FAIL: {

            u_int16_t sess_fail_len = avp_len - AVP_HEADER_LEN - _vendor_id;

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
                               "\"sess-server-failover\":%s,", sess_fail_type);
            break;
        }

        case ORIGIN_HOST: {

            u_int16_t org_host_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            org_host = calloc(org_host_len, sizeof(char));
            memcpy(org_host, start, org_host_len);

            start += (org_host_len + padd);   // move pointer forward
            offset += (org_host_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"origin-host\":%s,", org_host);
            break;
        }

        case DEST_HOST: {

            u_int16_t dst_host_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            dst_host = calloc(dst_host_len, sizeof(char));
            memcpy(dst_host, start, dst_host_len);

            start += (dst_host_len + padd);   // move pointer forward
            offset += (dst_host_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"destination-host\":%s,", dst_host);
            break;
        }

        case ORIGIN_REALM: {

            u_int16_t org_realm_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            org_realm = calloc(org_realm_len, sizeof(char));
            memcpy(org_realm, start, org_realm_len);

            start += (org_realm_len + padd);   // move pointer forward
            offset += (org_realm_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"origin-realm\":%s,", org_realm);
            break;
        }

        case DEST_REALM: {

            u_int16_t dst_realm_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            dst_realm = calloc(dst_realm_len, sizeof(char));
            memcpy(dst_realm, start, dst_realm_len);

            start += (dst_realm_len + padd);   // move pointer forward
            offset += (dst_realm_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"destination-realm\":%s,", dst_realm);
            break;
        }

        case AUTH_APP_ID: {

            u_int16_t auth_app_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            auth_app_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            // TODO: value is not correct. Must find a way to calculate it right for 3gpp

            start += (auth_app_len + padd);   // move pointer forward
            offset += (auth_app_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"auth-app-ID\":%u,", auth_app_id);
            break;
        }

        case VENDOR_ID: {

            u_int16_t vend_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            vend_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            start += (vend_len + padd);   // move pointer forward
            offset += (vend_len + padd);  // update offset

            // put buffer in JSON buffer
            if(vend_id == _3GPP_ID)
                js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                                   "\"vendor-ID\":%s,", "3GPP");
            else
                js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                                   "\"vendor-ID\":%u,", vend_id);
            break;
        }

        case RES_CODE: {

            char rc_buff[30] = {0};
            u_int16_t res_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            res_code = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            start += (res_len + padd);   // move pointer forward
            offset += (res_len + padd);  // update offset

            if(res_code >= 1000 && res_code < 2000) strncpy(rc_buff, "Informational", strlen("Informational"));
            else if(res_code >= 2000 && res_code < 3000) strncpy(rc_buff, "Success", strlen("Success"));
            else if(res_code >= 3000 && res_code < 4000) strncpy(rc_buff, "Protocol Errors", strlen("Protocol Errors"));
            else if(res_code >= 4000 && res_code < 5000) strncpy(rc_buff, "Transient Failures", strlen("Transient Failures"));
            else if(res_code >= 5000 && res_code < 6000) strncpy(rc_buff, "Permanent Failure", strlen("Permanent Failure"));

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"res-code\":%s,", rc_buff);
            break;
        }

        case ORIGIN_ST_ID: {

            u_int16_t orgst_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            orgst_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            start += (orgst_len + padd);   // move pointer forward
            offset += (orgst_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"origin-state-id\":%u,", orgst_id);
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

            start += (time_len + padd);  // move pointer forward
            offset += (time_len + padd); // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"event-timestamp\":""%s"",", buff_tm);
            break;
        }

        case EXP_RES: { // Grouped

            u_int16_t exp_res_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            break;
        }

        case EXP_RES_CODE: {

            u_int16_t exp_res_code_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            exp_res_code = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            start += (exp_res_code_len + padd);   // move pointer forward
            offset += (exp_res_code_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"Exp-Result-Code\":%u,", exp_res_code);
            break;
        }

            // 3GPP
        case PUB_ID: {

            u_int16_t pub_id_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            pub_id = calloc(pub_id_len, sizeof(char));
            memcpy(pub_id, start, pub_id_len);

            start += (pub_id_len + padd);   // move pointer forward
            offset += (pub_id_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"public-identity\":%s,", pub_id);
            break;
        }

        case VISIT_NET_ID: {

            u_int16_t visit_net_id_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            visit_net_id = calloc(visit_net_id_len, sizeof(char));
            memcpy(visit_net_id, start, visit_net_id_len);

            start += (visit_net_id_len + padd);   // move pointer forward
            offset += (visit_net_id_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"visit-network-id\":%s,", visit_net_id);
            break;
        }

        case SERVER_NAME: {

            u_int16_t srv_name_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            srv_name = calloc(srv_name_len, sizeof(char));
            memcpy(srv_name, start, srv_name_len);

            start += (srv_name_len + padd);   // move pointer forward
            offset += (srv_name_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"server-name\":%s,", srv_name);
            break;
        }

        case USER_DATA: {

            u_int16_t user_data_len = avp_len - AVP_HEADER_LEN - _vendor_id;
            user_data = calloc(user_data_len, sizeof(char));
            memcpy(user_data, start, user_data_len);

            start += (user_data_len + padd);   // move pointer forward
            offset += (user_data_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"user-data\":%s,", user_data);
            break;
        }

        default: {
            start += (avp_len - unk + padd);
            offset += (avp_len - unk + padd);
        }
        } // switch
    }

    js_ret += snprintf((json_buffer + js_ret - 1), (buffer_len - js_ret + 1), "}");

    return 0; // OK
}

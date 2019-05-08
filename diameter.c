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
static char *session_id;
static char *vendor_spec_id;
static char *auth_sess_st;
static char *org_host;
static char *dst_host;
static char *org_realm;
static char *dst_realm;
static u_int32_t auth_app_id;
static u_int32_t vend_id;
static u_int32_t res_code;
static u_int32_t orgst_id;
char buff_tm[30] = {0};

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
    for (i = AC, j = 0; i <= ST; i++, j++) {
        if(i == com_code) {
            snprintf(com_string, 3, "%s", com_diam_base_arr[j]);
            return DIAM_BASE;
        }
    }
    // check for 3GPP command
    for (i = UA, j = 0; i <= EC; i++, j++) {
        if(i == com_code) {
            /* printf("string = %s\n", com_diam_base_arr[j]); */
            snprintf(com_string, 3, "%s", com_diam_3gpp_arr[j]);
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
    const char com_string[5] = {0};
    const char app_string[5] = {0};
    // start and end pointers
    /* const u_char *start; */
    /* const u_char *end; */

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
    app_id = diameter->app_id[3] + (diameter->app_id[2] << 8) + (diameter->app_id[1] << 8) + (diameter->app_id[0] << 8);
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
    js_ret += snprintf((json_buffer + js_ret), buffer_len, "{ \"diameter_report_information\":{ ");

    while(start < end && offset < length) {

        // Info from AVP headers
        u_int32_t avp_code;
        u_int8_t  flag;
        u_int16_t avp_len;
        u_int16_t l;
        u_int8_t  padd = 0;
        u_int32_t vendor_id;

        // Header AVP
        struct avp_header_t *avp = (struct avp_header_t *) start;

        // calculate AVP code
        avp_code = ntohl(avp->code);

        // calculate AVP length
        avp_len = avp->length[2] + (avp->length[1] << 8) + (avp->length[0] << 8);

        // move pointer forward and increase the offset
        start += 8;
        offset += 8;

        // check AVP flag - search the presence of Vendor-ID field (4 bytes optional)
        if(CHECK_BIT(avp->flag, 8) == 1) {
            vendor_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);
            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"vendor-ID\":%u, ", vendor_id);
            start += 4;
            offset += 4;
        }

        switch(avp_code) {

        case SESS_ID: {

            u_int16_t sess_id_len = avp_len - AVP_HEADER_LEN;
            session_id = calloc(sess_id_len, sizeof(char));
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
                               "\"session-ID\":%s, ", session_id);
        }

        case VENDOR_SPEC_ID: {

            u_int16_t vend_spec_id_len = avp_len - AVP_HEADER_LEN;
            vendor_spec_id = calloc(vend_spec_id_len, sizeof(char));
            memcpy(vendor_spec_id, start, vend_spec_id_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }
            start += (vend_spec_id_len + padd);   // move pointer forward
            offset += (vend_spec_id_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"vendor-spec-ID\":%s, ", vendor_spec_id);
        }

        case AUTH_SESS_ST: {

            u_int16_t auth_sess_len = avp_len - AVP_HEADER_LEN;
            auth_sess_st = calloc(auth_sess_len, sizeof(char));
            memcpy(auth_sess_st, start, auth_sess_len);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }
            start += (auth_sess_len + padd);   // move pointer forward
            offset += (auth_sess_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"auth-sess-st\":%s, ", auth_sess_st);
        }

        case ORIGIN_HOST: {

            u_int16_t org_host_len = avp_len - AVP_HEADER_LEN;
            org_host = calloc(org_host_len, sizeof(char));
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
                               "\"origin-host\":%s, ", org_host);
        }

        case DEST_HOST: {

            u_int16_t dst_host_len = avp_len - AVP_HEADER_LEN;
            dst_host = calloc(dst_host_len, sizeof(char));
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
                               "\"destination-host\":%s, ", dst_host);
        }

        case ORIGIN_REALM: {

            u_int16_t org_realm_len = avp_len - AVP_HEADER_LEN;
            org_realm = calloc(org_realm_len, sizeof(char));
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
                               "\"origin-realm\":%s, ", org_realm);
        }

        case DEST_REALM: {

            u_int16_t dst_realm_len = avp_len - AVP_HEADER_LEN;
            dst_realm = calloc(dst_realm_len, sizeof(char));
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
                               "\"destination-realm\":%s, ", dst_realm);
        }

        case AUTH_APP_ID: {

            u_int16_t auth_app_len = avp_len - AVP_HEADER_LEN;
            auth_app_id = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

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
                               "\"auth-app-ID\":%u, ", auth_app_id);
        }

        case VENDOR_ID: {

            u_int16_t vend_len = avp_len - AVP_HEADER_LEN;
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
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"vendor-ID\":%u, ", vend_id);
        }

        case RES_CODE: {

            u_int16_t res_len = avp_len - AVP_HEADER_LEN;
            res_code = start[3] + (start[2] << 8) + (start[1] << 8) + (start[0] << 8);

            // check for padding
            l = avp_len;
            padd = 0;
            while(l % 4 != 0) {
                padd++;	l++;
            }

            start += (res_len + padd);   // move pointer forward
            offset += (res_len + padd);  // update offset

            // put buffer in JSON buffer
            js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                               "\"res-code\":%u, ", res_code);
        }

        case ORIGIN_ST_ID: {

            u_int16_t orgst_len = avp_len - AVP_HEADER_LEN;
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
        }

        case TIMESTAMP: {

            u_int16_t time_len = avp_len - AVP_HEADER_LEN;
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
                               "\"event-timestamp\":""%s"", ", buff_tm);

        }

        } // switch


    /*     switch(avp_code) { */

    /*         // 461 */
    /*     case SERV_CONTX_ID: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         u_int16_t serv_contx_len = avp_len - AVP_HEADER_LEN; */
    /*         serv_contx_id = calloc(serv_contx_len, sizeof(char)); */
    /*         memcpy(serv_contx_id, pp, serv_contx_len); */

    /*         // check for padding */
    /*         l = avp_len; */
    /*         padd = 0; */
    /*         while(l % 4 != 0) { */
    /*             padd++;	l++; */
    /*         } */

    /*         pp = pp + serv_contx_len + padd; // move pointer forward */
    /*         offset += avp_len + padd; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            "\"service-context-ID\":%s, ", serv_contx_id); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 443 */
    /*     case SUBSCR_ID: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         // 1 */
    /*         struct avp_header_t *avp_sub_id_data = (struct avp_header_t *) pp; */
    /*         u_int16_t avp_sub_id_lenD = avp_sub_id_data->length[2] + (avp_sub_id_data->length[1] << 8) + (avp_sub_id_data->length[0] << 8); */
    /*         u_int16_t dlen = avp_sub_id_lenD - AVP_HEADER_LEN; */
    /*         char * subscr_id_data = calloc(dlen, sizeof(char)); */
    /*         pp = pp + AVP_HEADER_LEN; */
    /*         memcpy(subscr_id_data, pp, dlen); */
    /*         pp = pp + dlen; */
    /*         // 2 */
    /*         struct avp_header_t * avp_sub_id_type = (struct avp_header_t *) pp; */
    /*         u_int16_t avp_sub_id_lenT = avp_sub_id_type->length[2] + (avp_sub_id_type->length[1] << 8) + (avp_sub_id_type->length[0] << 8); */
    /*         pp = pp + AVP_HEADER_LEN; */
    /*         u_int32_t subscr_id_type = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8); */
    /*         u_int16_t tlen = avp_sub_id_lenT - AVP_HEADER_LEN; */
    /*         pp = pp + tlen; */

    /*         // check for padding */
    /*         l = avp_len; */
    /*         padd = 0; */
    /*         while(l % 4 != 0) { */
    /*             padd++;	l++; */
    /*         } */

    /*         pp = pp + padd; // move pointer forward */
    /*         offset += avp_len + padd; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            SUBSCR_ID_JSON, subscr_id_data, subscr_id_type); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 440 */
    /*     case SERV_PAR_INFO: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         // 1 */
    /*         struct avp_header_t *avp_serv_par_type = (struct avp_header_t *) pp; */
    /*         u_int16_t avp_serv_par_Tlen = avp_serv_par_type->length[2] + (avp_serv_par_type->length[1] << 8) + (avp_serv_par_type->length[0] << 8); */
    /*         pp = pp + AVP_HEADER_LEN; */
    /*         u_int32_t serv_par_info_type = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8); */
    /*         u_int16_t Tlen = avp_serv_par_Tlen - AVP_HEADER_LEN; */
    /*         pp = pp + Tlen; */
    /*         // 2 */
    /*         struct avp_header_t * avp_serv_par_value = (struct avp_header_t *) pp; */
    /*         u_int16_t avp_serv_par_Vlen = avp_serv_par_value->length[2] + (avp_serv_par_value->length[1] << 8) + (avp_serv_par_value->length[0] << 8); */
    /*         u_int16_t Vlen = avp_serv_par_Vlen - AVP_HEADER_LEN; */
    /*         char * serv_par_value = calloc(Vlen, sizeof(char)); */
    /*         pp = pp + AVP_HEADER_LEN; */
    /*         memcpy(serv_par_value, pp, Vlen); */
    /*         pp = pp + Vlen; */

    /*         // check for internal padding */
    /*         l = avp_serv_par_Vlen; */
    /*         padd = 0; */
    /*         while(l % 4 != 0) { */
    /*             padd++;	l++; */
    /*         } */
    /*         pp = pp + padd; // move pointer forward */

    /*         // check for padding */
    /*         l = avp_len; */
    /*         padd = 0; */
    /*         while(l % 4 != 0) { */
    /*             padd++;	l++; */
    /*         } */

    /*         pp = pp + padd; // move pointer forward */
    /*         offset += avp_len + padd; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            SERV_PARAM_JSON, serv_par_info_type, serv_par_value); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 415 */
    /*     case CC_REQ_NUM: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         u_int16_t cc_req_num_len = avp_len - AVP_HEADER_LEN; */
    /*         cc_req_num = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8); */

    /*         // check for padding */
    /*         l = avp_len; */
    /*         padd = 0; */
    /*         while(l % 4 != 0) { */
    /*             padd++;	l++; */
    /*         } */

    /*         pp = pp + cc_req_num_len + padd; // move pointer forward */
    /*         offset += avp_len + padd; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            "\"CC-request-number\":%u, ", cc_req_num); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 416 */
    /*     case CC_REQ_TYPE: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         u_int16_t cc_req_type_len = avp_len - AVP_HEADER_LEN; */
    /*         cc_req_type = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8); */

    /*         // check for padding */
    /*         l = avp_len; */
    /*         padd = 0; */
    /*         while(l % 4 != 0) { */
    /*             padd++;	l++; */
    /*         } */

    /*         pp = pp + cc_req_type_len + padd; // move pointer forward */
    /*         offset += avp_len + padd; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            "\"CC-request-type\":%u, ", cc_req_type); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 448 */
    /*     case VALID_TIME: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         u_int16_t valid_len = avp_len - AVP_HEADER_LEN; */
    /*         valid_time = pp[3] + (pp[2] << 8) + (pp[1] << 8) + (pp[0] << 8); */

    /*         // check for padding */
    /*         l = avp_len; */
    /*         padd = 0; */
    /*         while(l % 4 != 0) { */
    /*             padd++;	l++; */
    /*         } */

    /*         pp = pp + valid_len + padd; // move pointer forward */
    /*         offset += avp_len + padd; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            "\"Validity-time\":%u, ", valid_time); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 437 */
    /*     case REQ_SERV_UNT: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         req_serv_unit = (struct req_serv_unit_t *) pp; */
    /*         u_int64_t req_value_dgt = req_serv_unit->value_dgt[7] + (req_serv_unit->value_dgt[6] << 8) + (req_serv_unit->value_dgt[5] << 8) + (req_serv_unit->value_dgt[4] << 8) + (req_serv_unit->value_dgt[3] << 8) + (req_serv_unit->value_dgt[2] << 8) + (req_serv_unit->value_dgt[1] << 8) + (req_serv_unit->value_dgt[0] << 8); */
    /*         u_int32_t req_currency_code = req_serv_unit->curr_code[3] + (req_serv_unit->curr_code[2] << 8) + (req_serv_unit->curr_code[1] << 8) + (req_serv_unit->curr_code[0] << 8); */

    /*         pp = pp + avp_len - AVP_HEADER_LEN; // move pointer forward */
    /*         offset += avp_len; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            REQ_SERV_JSON, req_value_dgt, req_currency_code); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 431 */
    /*     case GRANT_SERV_UNT: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         grant_serv_unit = (struct grant_serv_unit_t *) pp; */
    /*         u_int64_t grant_value_dgt = grant_serv_unit->value_dgt[7] + (grant_serv_unit->value_dgt[6] << 8) + (grant_serv_unit->value_dgt[5] << 8) + (grant_serv_unit->value_dgt[4] << 8) + (grant_serv_unit->value_dgt[3] << 8) + (grant_serv_unit->value_dgt[2] << 8) + (grant_serv_unit->value_dgt[1] << 8) + (grant_serv_unit->value_dgt[0] << 8); */
    /*         u_int32_t grant_currency_code = grant_serv_unit->curr_code[3] + (grant_serv_unit->curr_code[2] << 8) + (grant_serv_unit->curr_code[1] << 8) + (grant_serv_unit->curr_code[0] << 8); */

    /*         pp = pp + avp_len - AVP_HEADER_LEN; // move pointer forward */
    /*         offset += avp_len; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            GRANT_SERV_JSON, grant_value_dgt, grant_currency_code); */
    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 446 */
    /*     case USED_SERV_UNT: */

    /*         pp = pp + AVP_HEADER_LEN; */
    /*         used_serv_unit = (struct used_serv_unit_t *) pp; */
    /*         u_int64_t used_value_dgt = used_serv_unit->value_dgt[7] + (used_serv_unit->value_dgt[6] << 8) + (used_serv_unit->value_dgt[5] << 8) + (used_serv_unit->value_dgt[4] << 8) + (used_serv_unit->value_dgt[3] << 8) + (used_serv_unit->value_dgt[2] << 8) + (used_serv_unit->value_dgt[1] << 8) + (used_serv_unit->value_dgt[0] << 8); */
    /*         u_int32_t used_currency_code = used_serv_unit->curr_code[3] + (used_serv_unit->curr_code[2] << 8) + (used_serv_unit->curr_code[1] << 8) + (used_serv_unit->curr_code[0] << 8); */

    /*         pp = pp + avp_len - AVP_HEADER_LEN; // move pointer forward */
    /*         offset += avp_len; // update offset */

    /*         // put buffer in JSON buffer */
    /*         js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret, */
    /*                            USED_SERV_JSON, used_value_dgt, used_currency_code); */

    /*         /\* printf("json_buffer = %s\n", json_buffer); *\/ */
    /*         break; */

    /*         // 456 */
    /*     case MULTI_SERV_CC: 	/\* TODO *\/ */
    /*         break; */

    /*     default: return -3; // error: avp->code unknown */

    /*     } */
    }

    js_ret += snprintf((json_buffer + js_ret - 2), (buffer_len - js_ret + 1), " }");

    return 0; // OK
}

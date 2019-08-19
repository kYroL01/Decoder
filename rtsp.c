/**
   RTSP dissector

   Copyright (C) 2016-2019 Michele Campus <michelecampus5@gmail.com>

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "globals.h"
#include "rtsp.h"

// Check if String s begins with the given prefix
static int starts_with(const char *s, const char *prefix) {

    if(strncmp(s, prefix, strlen(prefix)) == 0)
        return 1;
    else
        return 0;
}


/**
   Parse packet and fill a JSON buffer
   @param  packet, size_payload, json_buffer, buffer_len
   @return 0 if pkt is rtsp and JSON buffer is created
   @return -1 in case of errors
**/
int rtsp_parser(const u_char *packet, int size_payload, char *json_buffer, int buffer_len) {

    int ret = -1, js_ret = 0;
    int total = 0;
    uint16_t l_inter = 0;
    char *p = packet;

    // check param
    if(!packet || size_payload == 0) {
        fprintf(stderr, "::Error:: parameters not valid\n");
        return -1;
    }

    // alloc memory for struct msg. This struct is filled after parsing
    rtsp_message *msg = malloc(1 * sizeof(rtsp_message));

    /* Check for Magic byte (interleaved pkt) */
    /**
       NOTE: now we just parsed the RTP pkt; 
       then we need to export in some way
     **/
    if(*p == MAGIC) {
        if(is_interleaved) {
            for(total = 0; total < size_payload; total += (l_inter + 4)) {
                p += 2; // magic + channel
                l_inter = ntohs((*(p+1) << 8) + *p);
                p += 2; // length
                // copy the buffer (RTP pkt)
                char *interleaved_buff = malloc(l_inter * sizeof(malloc));
                memcpy(interleaved_buff, p, l_inter);
                p += l_inter;
                if(l_inter != 0)
                    printf("RTSP Interleaved Frame found - RTP packet saved in buffer (length = %d)\n", l_inter);
            }
        }
        else return -2; // ERROR - found MAGIC but not interleaved in SETUP
    }
    
    else {
    ret = rtsp_message_parser(msg, (char*) packet, size_payload);

    /**
       Create JSON buffer
    **/
    /* { */
    js_ret += snprintf((json_buffer + js_ret), buffer_len, "{ \"rtsp_report_information\":{ ");
    // TYPE
    if(msg->msg_type == 0)
        js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                           "\"type\":%s, ", "request");
    else
        js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                           "\"type\":%s, ", "response");
    // COMMAND
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"command\":%s, ", (msg->command == NULL) ? "-" : msg->command);
    // STATUS CODE
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"status code\":%s, ", (msg->status_code == NULL) ? "-" : msg->status_code);
    // SEQNUM
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"seq-num\":%s, ", (msg->seq_num == NULL) ? "-" : msg->seq_num);
    // SESSION
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"session\":%s, ", (msg->session == NULL) ? "-" : msg->session);
    // SERVER
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"server\":%s, ", (msg->server == NULL) ? "-" : msg->server);
    // URI
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"uri\":%s, ", (msg->uri == NULL) ? "-" : msg->uri);
    // UA
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"user-agent\":%s, ", (msg->ua == NULL) ? "-" : msg->ua);
    // CONTENT BASE
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"content-base\":%s, ", (msg->content_base == NULL) ? "-" : msg->content_base);
    // CONTENT LEN
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"content-len\":%s, ", (msg->content_len == NULL) ? "-" : msg->content_len);
    // CONTENT TYPE
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"content-type\":%s, ", (msg->content_type == NULL) ? "-" : msg->content_type);
    // PROTOCOL
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                           "\"protocol\":%s, ", (msg->protocol == NULL) ? "-" : msg->protocol);
    // CACHE CONTROL
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"cache control\":%s, ", (msg->cache_control == NULL) ? "-" : msg->cache_control);
    // TRANSPORT
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"transport\":%s ", (msg->transport == NULL) ? "-" : msg->transport);
    // SDP
    js_ret += snprintf((json_buffer + js_ret), buffer_len - js_ret,
                       "\"sdp\":%s ", (msg->sdp == NULL) ? "-" : msg->sdp);
    /* } */
    js_ret += snprintf((json_buffer + js_ret - 1), (buffer_len - js_ret + 1), " }");
    js_ret += snprintf((json_buffer + js_ret - 1), (buffer_len - js_ret + 1), " }");

    if(ret != 0) return -1;
    }
    
    return 0;
}


// Given an RTSP message string rtspMessage, parse it into an RTSP_MESSAGE struct msg
int rtsp_message_parser(rtsp_message *msg, char *rtspMessage, int length) {

    /** Declaration of variables to save in msg **/
    char *protocol = NULL;
    char *uri = NULL;
    char *ua = NULL;
    char *command = NULL;
    char *seq_num = NULL;
    char *status_code = NULL;
    char *status_str = NULL;
    char *server = NULL;
    char *cache_control = NULL;
    char *content_base = NULL;
    char *content_type = NULL;
    char *content_len = NULL;
    char *last_mod = NULL;
    char *transport = NULL;
    char *session = NULL;
    char *range = NULL;
    char *sdp = NULL;
    char flag;

    // Variables for parsing
    char *token;
    char *end_check;
    int  exit_code;
    int  is_sdp = 0;
    char message_ended = 0;

    // Delimeter for strtok()
    char *delim = " \r\n";
    char *end = "\r\n";
    char *opt_delim = " :\r\n";

    /* Life cycle */
    /**
       1) Check if the message is Request or Response
       2) For every Req/Resp pair, check the Command types
       3) For every command, extract the Header fields to JSON
    **/

    // Put the raw message into a string
    char *messageBuffer = malloc(length + 1);
    if(messageBuffer == NULL) {
        exit_code = RTSP_ERROR_NO_MEMORY;
        goto ExitFailure;
    }
    memcpy(messageBuffer, rtspMessage, length);

    // The payload logic depends on a null-terminator at the end
    messageBuffer[length] = 0;

    /**
       Get the first token of the message
       -  the msg should be a request or response
       -- if token is "RTSP" the msg is a response (value must be saved)
       -- if token is a Method definition the msg is a request (value must be saved)
    **/
    // Get the token
    token = strtok(messageBuffer, delim);
    if(token == NULL) {
        exit_code = RTSP_ERROR_MALFORMED;
        goto ExitFailure;
    }

    /**
       ### The message is a RESPONSE ###
    **/
    // parse PROTOCOL, STATUS_CODE and STATUS_STR
    if(starts_with(token, "RTSP")) {
        flag = RESPONSE;
        // Save the protocol
        protocol = token;
        // Save the status code
        token = strtok(NULL, delim);
        status_code = token;
        if(token == NULL) {
            exit_code = RTSP_ERROR_MALFORMED;
            goto ExitFailure;
        }
        // Get the status string
        status_str = strtok(NULL, end);
        if(status_str == NULL) {
            exit_code = RTSP_ERROR_MALFORMED;
            goto ExitFailure;
        }
    }

    /**
       ### The message is a REQUEST ###
    **/
    else {
        // save FLAG
        flag = REQUEST;
        // save COMMAND
        command = token;
        // save the URI
        uri = strtok(NULL, delim);
        if(uri == NULL) {
            exit_code = RTSP_ERROR_MALFORMED;
            goto ExitFailure;
        }
        // save the PROTOCOL
        protocol = strtok(NULL, delim);
        if(protocol == NULL) {
            exit_code = RTSP_ERROR_MALFORMED;
            goto ExitFailure;
        }
    }
    // check protocol for both REQUEST and RESPONSE
    if(strcmp(protocol, "RTSP/1.0")) {
        exit_code = RTSP_ERROR_MALFORMED;
        goto ExitFailure;
    }

    /**
       Header Field parsing
       - rest of pkt must be parsed to extract header field, which give us much more details
       - Header Field list in .h
    **/
    // Parse remaining payload
    while(token != NULL)
    {
        token = strtok(NULL, opt_delim);
        if(token != NULL) {
            /**
               Save Header fields value
            **/
            // CSEQ
            if(!strncmp(token, "CSeq", strlen("CSeq"))) {
                token = strtok(NULL, delim);
                seq_num = token;
            }
            // USER-AGENT
            else if(!strncmp(token, "User-Agent", strlen("User-Agent"))) {
                token = strtok(NULL, delim);
                ua = token;
            }
            // SERVER
            else if(!strncmp(token, "Server", strlen("Server"))) {
                token = strtok(NULL, end);
                server = token+1; // +1 to cut the initial space
            }
            // CACHE-CONTROL
            else if(!strncmp(token, "Cache-Control", strlen("Cache-Control"))) {
                token = strtok(NULL, end);
                cache_control = token+1; // +1 to cut the initial space
            }
            // CONTENT-TYPE
            else if(!strncmp(token, "Content-Type", strlen("Content-type"))) {
                token = strtok(NULL, delim);
                content_type = token;
                if(!strncmp(content_type, "application/sdp", strlen("application/sdp")))
                    is_sdp = 1;
            }
            // CONTENT-LENGTH
            else if(!strncmp(token, "Content-Length", strlen("Content-Length"))) {
                token = strtok(NULL, delim);
                content_len = token;
            }
            // CONTENT-BASE
            else if(!strncmp(token, "Content-Base", strlen("Content-Base"))) {
                token = strtok(NULL, delim);
                content_base = token;
            }
            // LAST-MODIFIED
            else if(!strncmp(token, "Last-Modified", strlen("Last-Modified"))) {
                token = strtok(NULL, end);
                last_mod = token+1;
            }
            // TRANSPORT
            else if(!strncmp(token, "Transport", strlen("Transport"))) {
                token = strtok(NULL, end);
                transport = token+1;
            }
            // SESSION
            else if(!strncmp(token, "Session", strlen("Session"))) {
                token = strtok(NULL, end);
                session = token+1;
            }
            // RANGE
            else if(!strncmp(token, "Range", strlen("Range"))) {
                token = strtok(NULL, delim);
                range = token;
            }
            // Discard option
            else {
                token = strtok(NULL, end);
            }

            /* Check if we're at the end of the message portion marked by \r\n\r\n
               end_check points to the remainder of messageBuffer after the token
            */
            end_check = &token[0] + strlen(token) + 1;

            // Check if we've hit the end of the message. The first \r is missing because it's been tokenized
            if(starts_with(end_check, "\n") && end_check[1] == '\0') {
                // End of the message
                message_ended = 1;
                break;
            }
            else if(starts_with(end_check, "\n\r\n")) {
                // check the presence of SDP string for RTSP session
                if(is_sdp == 1) {
                    sdp = end_check+3; // move pointer after \n\r\n
                    is_sdp = 0;
                }
                // End of the message
                message_ended = 1;
                break;
            }
        }
    }
    // If we never encountered the double CRLF, then the message is malformed!
    if(!message_ended) {
        exit_code = RTSP_ERROR_MALFORMED;
        goto ExitFailure;
    }

    /* Check if we will expect interleaved binary data (RTSP Interleaved Frame) */
    if(flag == REQUEST && (!strncmp(command, "SETUP", strlen("SETUP")))) {
        // parse command "transport" to find string "interleaved"
        if(strstr(transport, "interleaved"))
            is_interleaved = 1;
    }

    /*** Create the MESSAGE with extracted meaningful fields ***/
    create_rtsp_message(msg, protocol, uri, command, seq_num, status_code,
                        server, ua, cache_control, content_len, content_type, content_base,
                        last_mod, range, session, transport, flag, sdp);

    // free allocated variables
    free(messageBuffer);

    return RTSP_SUCCESS;

 ExitFailure:
    return exit_code;
}


// Create new RTSP message struct with response data
void create_rtsp_message(rtsp_message *msg, char *protocol, char *uri, char *command, char *seq_num,
                         char *status_code, char *server, char *ua, char *cache_control, char *content_len,
                         char *content_type, char *content_base, char *last_mod, char *range, char *session,
                         char *transport, char msg_type, char *sdp) {

    // Basic informations
    msg->cache_control = cache_control;
    msg->content_base = content_base;
    msg->content_len = content_len;
    msg->content_type = content_type;
    msg->last_mod = last_mod;
    msg->range = range;
    msg->session = session;
    msg->status_code = status_code;
    msg->transport = transport;
    msg->msg_type = msg_type;
    msg->command = command;
    msg->protocol = protocol;
    msg->status_code = status_code;
    msg->seq_num = seq_num;
    msg->ua = ua;
    msg->uri = uri;
    msg->server = server;
    // SDP for RTSP session
    msg->sdp = sdp;
}

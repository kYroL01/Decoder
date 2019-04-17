/**
   RTSP dissector

   decoder: parsing and classification of traffic
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
#include "rtsp.h"

// Check if String s begins with the given prefix
static int starts_with(const char *s, const char *prefix) {

    if (strncmp(s, prefix, strlen(prefix)) == 0)
        return 1;
    else
        return 0;
}

/* // Gets the length of the message */
/* static int get_message_length(prtsp_message msg) { */
/*     poption_item *current; */

/*     // Initialize to 1 for null terminator */
/*     size_t count = 1; */

/*     // Add the length of the protocol */
/*     count += strlen(msg->protocol); */

/*     // Add length of request-specific strings */
/*     if (msg->type == REQUEST) { */
/*         count += strlen(msg->message.request.command); */
/*         count += strlen(msg->message.request.uri); */
/*         // two spaces and \r\n */
/*         count += MESSAGE_END_LENGTH; */
/*     } */
/*     // Add length of response-specific strings */
/*     else { */
/*         char statusCodeStr[16]; */
/*         sprintf(statusCodeStr, "%d", msg->message.response.statusCode); */
/*         count += strlen(statusCodeStr); */
/*         count += strlen(msg->message.response.statusString); */
/*         // two spaces and \r\n */
/*         count += MESSAGE_END_LENGTH; */
/*     } */
/*     // Count the size of the options */
/*     current = msg->options; */

/*     while (current) { */
/*         count += strlen(current->option); */
/*         count += strlen(current->content); */
/*         // :[space] and \r\n */
/*         count += MESSAGE_END_LENGTH; */
/*         current = current->next; */
/*     } */

/*     // /r/n ending */
/*     count += CRLF_LENGTH; */
/*     count += msg->payloadLength; */

/*     return (int)count; */
/* } */

int rtsp_parser(const u_char *packet, int size_payload, char *json_buffer, int buffer_len) {

    int ret = -1;

    // check param
    if(!packet || size_payload == 0) {
        fprintf(stderr, "::Error:: parameters not valid\n");
        return -1;
    }

    // alloc memory for struct msg. This struct is filled after parsing
    rtsp_message *msg = malloc(1 * sizeof(rtsp_message));

    ret = rtsp_message_parser(msg, (char*) packet, size_payload);

    // TODO: fill the JSON buffer

    if(ret != RTSP_SUCCESS) return -1;

    return RTSP_SUCCESS;
}


// Given an RTSP message string rtspMessage, parse it into an RTSP_MESSAGE struct msg
int rtsp_message_parser(rtsp_message *msg, char *rtspMessage, int length) {

    /** Declaration of variables to save in msg **/
    char *protocol = NULL;
    char *uri = NULL;
    char *command = NULL;
    char *sequence = NULL;
    char *status_code = NULL;
    char *status_str = NULL;
    char *header_field_name = NULL;
    char *header_field_val = NULL;
    char *server = NULL;
    char flag;

    char *token;
    char *endCheck;
    char messageEnded = 0;
    int  exitCode;

    // Delimeter for strtok()
    char *delim = " \r\n";
    char *end = "\r\n";
    char *optDelim = " :\r\n";
    char typeFlag = IS_HEADER_FIELD; // if Header fields are present == 0, else == 1

    /* Life cycle */
    /**
       1) Check if the message is Request or Response
       2) For every Req/Resp pair, check the Command types
       3) For every command, extract the Header fields to JSON
    **/

    // Put the raw message into a string we can use
    char *messageBuffer = malloc(length + 1);
    if (messageBuffer == NULL) {
        exitCode = RTSP_ERROR_NO_MEMORY;
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
    if (token == NULL) {
        exitCode = RTSP_ERROR_MALFORMED;
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
            exitCode = RTSP_ERROR_MALFORMED;
            goto ExitFailure;
        }
        // Get the status string
        status_str = strtok(NULL, end);
        if (statusStr == NULL) {
            exitCode = RTSP_ERROR_MALFORMED;
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
        if (uri == NULL) { // URI
            exitCode = RTSP_ERROR_MALFORMED;
            goto ExitFailure;
        }
        //save the PROTOCOL
        protocol = strtok(NULL, delim);
        if (protocol == NULL) {
            exitCode = RTSP_ERROR_MALFORMED;
            goto ExitFailure;
        }
        // Response field - we don't care about it here
        /* statusStr = NULL; */
    }
    if (strcmp(protocol, "RTSP/1.0")) {
        exitCode = RTSP_ERROR_MALFORMED;
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
        token = strtok(NULL, typeFlag == IS_HEADER_FIELD ? optDelim : end);
        if(token != NULL) {

            /* TODO check for the others header fields */
            if(starts_with(token, "Server")) {
                /* TODO */
            }

            // Save Header field value
            if(typeFlag == IS_HEADER_FIELD) {
                // parse for name
                header_field_name = token;
                // parse for value
                token = strtok(NULL, delim);
                header_field_val = token;

                /**
                   Check if we're at the end of the message portion marked by \r\n\r\n
                   endCheck points to the remainder of messageBuffer after the token
                **/
                endCheck = &token[0] + strlen(token) + 1;

                // Check if we've hit the end of the message. The first \r is missing because it's been tokenized
                if(starts_with(endCheck, "\n") && endCheck[1] == '\0') {
                    // End of the message
                    messageEnded = 1;
                    break;
                }
                else if(starts_with(endCheck, "\n\r\n")) {
                    // End of the message
                    messageEnded = 1;
                    break;
                }
            }
        }
    }
    // If we never encountered the double CRLF, then the message is malformed!
    if (!messageEnded) {
        exitCode = RTSP_ERROR_MALFORMED;
        goto ExitFailure;
    }

    // Get sequence number as an integer
    sequence = get_option_content(options, "CSeq");
    if (sequence != NULL) {
        sequenceNum = atoi(sequence);
    }
    else {
        sequenceNum = SEQ_INVALID;
    }
    // Package the new parsed message into the struct
    if (flag == REQUEST) {
        create_rtsp_request(msg, messageBuffer, FLAG_ALLOCATED_MESSAGE_BUFFER | FLAG_ALLOCATED_OPTION_ITEMS, command, uri,
            protocol, sequenceNum, options, payload, payload ? length - (int)(messageBuffer - payload) : 0);
    }
    else {
        create_rtsp_response(msg, messageBuffer, FLAG_ALLOCATED_MESSAGE_BUFFER | FLAG_ALLOCATED_OPTION_ITEMS, protocol, statusCode,
            statusStr, sequenceNum, options, payload, payload ? length - (int)(messageBuffer - payload) : 0);
    }
    return RTSP_SUCCESS;

ExitFailure:
    if (options) {
        free_option_list(options);
    }
    if (messageBuffer) {
        free(messageBuffer);
    }
    return exitCode;
}


// Create new RTSP message struct with response data
void create_rtsp_message(prtsp_message msg, char *protocol, char *uri, char *command, char *sequence,
                         char *header_field_name, char *header_field_value, char msg_type) {

    // Message Type
    if(msg_type == REQUEST)
        strncpy(msg->flags, "Request", strlen("Request"));

    msg->protocol = protocol;
    msg->uri = uri;
    msg->command = command;
    msg->sequence = sequence;
    msg->geader_field_name = header_field_name;
    msg->geader_field_val = header_field_val;

}

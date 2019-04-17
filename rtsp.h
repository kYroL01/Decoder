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
#ifndef RTSP_H
#define RTSP_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define IS_HEADER_FIELD 0

#define RTSP_SUCCESS 0
#define RTSP_ERROR_NO_MEMORY -1
#define RTSP_ERROR_MALFORMED -2

#define SEQ_INVALID -1

#define FLAG_ALLOCATED_OPTION_FIELDS 0x1
#define FLAG_ALLOCATED_MESSAGE_BUFFER 0x2
#define FLAG_ALLOCATED_OPTION_ITEMS 0x4
#define FLAG_ALLOCATED_PAYLOAD 0x8

#define CRLF_LENGTH 2
#define MESSAGE_END_LENGTH (2 + CRLF_LENGTH)

/*** RTSP message type ***/
/**
   There are two types of message:
   - Request (from Client to Server)
   - Response (from Server to Client)
**/
#define REQUEST 0
#define RESPONSE 1

/*** Command definition ***/
/**
   The command token indicates the method to be performed on the resource
   identified by the Request-URI
**/
/*
  command           direction        object     requirement
  DESCRIBE          C->S             P,S        recommended
  ANNOUNCE          C->S, S->C       P,S        optional
  GET_PARAMETER     C->S, S->C       P,S        optional
  OPTIONS           C->S, S->C       P,S        required (S->C: optional)
  PAUSE             C->S             P,S        recommended
  PLAY              C->S             P,S        required
  RECORD            C->S             P,S        optional
  REDIRECT          S->C             P,S        optional
  SETUP             C->S             S          required
  SET_PARAMETER     C->S, S->C       P,S        optional
  TEARDOWN          C->S             P,S        required
*/

/**** Header Field Definitions ****/
/**
   Summary of the header fields used by RTSP (RFC 2326 RTSP 1.0)
   - type "g" designates general request headers to be found in both requests and responses
   - type "R" designates request headers
   - type "r" designates response headers
   - type "e" designates entity header fields
**/
/*
   Header               type   support   methods
   Accept               R      opt.      entity
   Accept-Encoding      R      opt.      entity
   Accept-Language      R      opt.      all
   Allow                r      opt.      all
   Authorization        R      opt.      all
   Bandwidth            R      opt.      all
   Blocksize            R      opt.      all but OPTIONS, TEARDOWN
   Cache-Control        g      opt.      SETUP
   Conference           R      opt.      SETUP
   Connection           g      req.      all
   Content-Base         e      opt.      entity
   Content-Encoding     e      req.      SET_PARAMETER
   Content-Encoding     e      req.      DESCRIBE, ANNOUNCE
   Content-Language     e      req.      DESCRIBE, ANNOUNCE
   Content-Length       e      req.      SET_PARAMETER, ANNOUNCE
   Content-Length       e      req.      entity
   Content-Location     e      opt.      entity
   Content-Type         e      req.      SET_PARAMETER, ANNOUNCE
   Content-Type         r      req.      entity
   CSeq                 g      req.      all
   Date                 g      opt.      all
   Expires              e      opt.      DESCRIBE, ANNOUNCE
   From                 R      opt.      all
   If-Modified-Since    R      opt.      DESCRIBE, SETUP
   Last-Modified        e      opt.      entity
   Proxy-Authenticate
   Proxy-Require        R      req.      all
   Public               r      opt.      all
   Range                R      opt.      PLAY, PAUSE, RECORD
   Range                r      opt.      PLAY, PAUSE, RECORD
   Referer              R      opt.      all
   Require              R      req.      all
   Retry-After          r      opt.      all
   RTP-Info             r      req.      PLAY
   Scale                Rr     opt.      PLAY, RECORD
   Session              Rr     req.      all but SETUP, OPTIONS
   Server               r      opt.      all
   Speed                Rr     opt.      PLAY
   Transport            Rr     req.      SETUP
   Unsupported          r      req.      all
   User-Agent           R      opt.      all
   Via                  g      opt.      all
   WWW-Authenticate     r      opt.      all
*/

// NEW STRUCT TODO: put in .h
typedef struct _RTSP_MESSAGE {
    char flags;
    char *protocol;
    char *uri;
    char *sequence;
    char *header_field_name;
    char *header_field_val;
    /* TODO list not finished: see the RFC */
    char *sdp; //
} rtsp_message;

int rtsp_message_parser(rtsp_message *msg, char *rtspMessage, int length);
void create_rtsp_message(rtsp_message *msg, char *messageBuffer, int flags, char *protocol, int statusCode, char *statusString, int sequenceNumber, poption_item *optionsHead, char *payload, int payloadLength);
/* void create_rtsp_response(prtsp_message msg, char *messageBuffer, int flags, char *protocol, int statusCode, char *statusString, int sequenceNumber, poption_item *optionsHead, char *payload, int payloadLength); */
/* void create_rtsp_request(prtsp_message msg, char *messageBuffer, int flags, char *command, char *target, char *protocol, int sequenceNumber, poption_item *optionsHead, char *payload, int payloadLength); */

#endif

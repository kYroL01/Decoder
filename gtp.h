/**
   Header file for GTP parser

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
#ifndef PARSER_GTP_H
#define PARSER_GTP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GTP_U     2152
#define GTP_C     2123
#define GTP_PRIME 3386

#define HEADER_LEN_GTP_U        8
#define HEADER_LEN_GTP_C_V1     8
#define HEADER_LEN_GTP_C_V2     4
#define HEADER_LEN_GTP_PRIME    6

/* Common header for GTP protocol */
struct gtp_header {
    u_int8_t flags, msg_type;
    u_int16_t msg_len;
};

/**
   Functions for the dissection
   @return GTP version
**/
// Parse packet, check if it's GTP and create JSON buffer with protocol information
int gtp_parser(const unsigned char *packet, int size_payload,  const u_int16_t src_port,
               const u_int16_t dst_port, char *json_buffer, int buffer_len);

#endif

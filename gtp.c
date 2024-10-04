/**
   GTP dissector

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
#include "gtp.h"

/**
   Parse packet and fill JSON buffer
   @param  packet, size_payload, json_buffer, buffer_len
   @return > 0 if pkt is GTP and JSON buffer is created. The number will reflects the GTP version
   @return -1 in case of errors
**/
int gtp_parser(const unsigned char *packet, int size_payload,  const u_int16_t src_port,
               const u_int16_t dst_port, char *json_buffer, int buffer_len)
{
    // check param
    if(!packet || size_payload == 0) {
        fprintf(stderr, "::Error:: parameters not valid\n");
        return -1;
    }

    if(size_payload > sizeof(struct gtp_header)) {

        u_int32_t gtp_u  = ntohs(2152);
        u_int32_t gtp_c  = ntohs(2123);
        u_int32_t gtp_prime = ntohs(3386);

        // cast to GTP header
        struct gtp_header *gtp = (struct gtp_header *) packet;

        u_int8_t version = (gtp->flags & 0xE0) >> 5;
        u_int8_t pt = (gtp->flags & 0x10) >> 4;
        u_int16_t msg_len = ntohs(gtp->msg_len);

        // GTP_U
        if((src_port == gtp_u) || (dst_port == gtp_u)) {
            if((version == 1) && (pt == 1) &&
               (size_payload >= HEADER_LEN_GTP_U) && (msg_len <= (size_payload - HEADER_LEN_GTP_U))) {
                printf("This is GTP-U\n");
                return 5;
            }
        }
        // GTP_C
        if((src_port == gtp_c) || (dst_port == gtp_c)) {
            if((version == 1) &&
                (size_payload >= HEADER_LEN_GTP_C_V1) &&
                (msg_len == (size_payload - HEADER_LEN_GTP_C_V1)) &&
                (msg_len >= 4 * (!!(gtp->flags & 0x07))) && (gtp->msg_type > 0 && gtp->msg_type <= 129)) {
                printf("This is GTP-C-V1\n");
                return 1;
            }
            if ((version == 2) && (msg_len == (size_payload - HEADER_LEN_GTP_C_V2))) {
                printf("This is GTP-C-V2\n");
                return 2;
            }
        }
        // GTP_PRIME
        if((src_port == gtp_prime) || (dst_port == gtp_prime)) {
            if((pt == 0) &&
               ((gtp->flags & 0x0E) >> 1 == 0x7) && (size_payload >= HEADER_LEN_GTP_PRIME) &&
               (msg_len <= (size_payload - HEADER_LEN_GTP_PRIME)) &&
               ((gtp->msg_type > 0 && gtp->msg_type <= 7) || gtp->msg_type == 240 || gtp->msg_type == 241)) {
                printf("This is GTP-C-PRIME\n");
                return 3;
            }
        }
    }

    // TODO extract filed and make a json buffer

    return 0;
}

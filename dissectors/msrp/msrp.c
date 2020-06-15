/**
   MSRP dissector

   Copyright (C) 2016-2020 Michele Campus <michelecampus5@gmail.com>

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
#include "msrp.h"

// Macro to check if the k-th bit is set (1) or not (0)
#define CHECK_BIT(var, k) ((var) & (1<<(k-1)))



/**
   Parse packet and fill JSON buffer
   @param  packet, size_payload, json_buffer, buffer_len
   @return 0 if pkt is diameter and JSON buffer is created
   @return -1 in case of errors
**/
int msrp_parser(const u_char *packet, int size_payload, char *json_buffer, int buffer_len)
{
    if(packet == NULL || size_payload == 0)
        return -1;

    uint8_t *sp;
    uint8_t *tmp;
    int offset_line;
    // define structs for msrp pkts
    struct msrp_send_t msrp_send;
    struct msrp_response_t msrp_resp;
    struct msrp_report_t msrp_report;
    // aux
    char buffer[LEN] = {0};    

    sp = packet;
    tmp = packet;
    offset_line = 0;
    
    for (; *sp; sp++)
    {
        if (*sp == '\r' && *(sp + 1) == '\n') /* end of this line */
        {
            memcpy(&buffer, sp, sp-tmp);
            printf("First line of MSRP header = %s\n", buffer);
            
        } // if \r\n
    } // for

    return 0;
}

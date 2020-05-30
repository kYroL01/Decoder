/**
   Parser for ncgp protocol

   decoder: parsing and classification traffic
   Copyright (C) 2016-2018 Michele Campus <fci1908@gmail.com>

   This file is part of decoder.

   [ The headers in this module follow the RFC 5246
   and the pcap analyzed to have a real conformity
   from theory and real traffic ]

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
#include <arpa/inet.h>
#include "ngcp.h"

struct msg_fake_sip * ngcp_parser(const u_char * payload,
                                  const u_int16_t size_payload)
{
    // pointer of beginning of payload
    const u_char *p = payload;

    // Fake msg SIP
    struct msg_fake_sip *msg_sf = NULL;
    // pointer to beginning of sdp payload
    const char *sdp = NULL;
    // pointer for call-id
    const char *call_id = NULL;
    // pointer for from-tag
    const char *from_tag = NULL;
    // pointer for to-tag
    const char *to_tag = NULL;
    // pointer for command type
    const char *comm = NULL;
    // flag for command type
    int flag = 0;

    // check parameters
    if(!payload || size_payload == 0)
    {
        fprintf(stderr, "error params in check NGCP\n");
        return NULL;
    }

    // allocate msg
    msg_sf = malloc(sizeof(struct msg_fake_sip) * 1);

    // check command type
    if((comm = strstr((const char *)payload, "offer")) != NULL)
    {
        msg_sf->comm_flag = 1;
        flag = OFFER;
    }
    else if((comm = strstr((const char *)payload, "answer")) != NULL)
    {
        msg_sf->comm_flag = 2;
        flag = ANSWER;
    }
    else if((comm = strstr((const char *)payload, "delete")) != NULL)
    {
        msg_sf->comm_flag = 3;
        flag = DELETE;
    }
    else
    {
        fprintf(stderr, "Only OFFER, ANSWER or DELETE command are supported - abort!\n");
        return NULL;
    }

    if(flag != DELETE)
    {
        // check if it's a sdp packet
        if((sdp = strstr((const char *)payload, "sdp")) == NULL)
        {
            fprintf(stderr, "error in check NGCP: no SDP found\n");
            return NULL;
        }

        // sdp length
        u_int16_t sdp_len = (100*(sdp[3]-'0'))+(10*(sdp[4]-'0'))+(sdp[5]-'0');
        // alloc space for raw sdp buffer in msg
        msg_sf->raw_sdp = calloc(sizeof(char), sdp_len+1); // +1 for \0 in the end

        // move sdp pointer for copy
        sdp = sdp + 7;

        // copy the magic cookie
        memcpy(msg_sf->magic, p, 13);
        // copy the sdp payload
        memcpy(msg_sf->raw_sdp, sdp, sdp_len);
        msg_sf->raw_sdp[sdp_len+1] = '\0';

        /**
        *** CALL-ID ***
        */
        // check if call-id is present
        if((call_id = strstr((const char *)payload, "call-id")) == NULL)
        {
            fprintf(stderr, "error in check NGCP: no CALL-ID found\n");
            return NULL;
        }
        // move call-id pointer
        call_id = call_id + 7;
        // call-id length
        u_int16_t call_id_len = (10*(call_id[0]-'0'))+((call_id[1]-'0'));
        // move call-id pointer
        call_id = call_id + 3;
        // copy the call-id
        memcpy(msg_sf->call_id, call_id, call_id_len);
        msg_sf->call_id[call_id_len+1] = '\0';

        /**
        *** FROM-TAG ***
        */
        // check if from-tag is present
        if((from_tag = strstr((const char *)payload, "from-tag")) == NULL)
        {
            fprintf(stderr, "error in check NGCP: no FROM-TAG found\n");
            return NULL;
        }
        // move from-tag pointer
        from_tag = from_tag + 8;

        // from-tag length
        u_int16_t from_tag_len = from_tag[0]-'0';

        // move from_tag pointer
        from_tag = from_tag + 2;
        // copy the from_tag
        memcpy(msg_sf->from_tag, from_tag, from_tag_len);
        msg_sf->from_tag[from_tag_len+1] = '\0';

        /**
        *** TO-TAG ***
        *** Note: to-tag field is present only in an answer pkt
        */
        if(flag == ANSWER)
        {
            // check if to-tag is present
            if((to_tag = strstr((const char *)payload, "to-tag")) == NULL)
            {
                fprintf(stderr, "error in check NGCP: no TO-TAG found\n");
                return NULL;
            }
            // move to-tag pointer
            to_tag = to_tag + 6;

            // to-tag length
            u_int16_t to_tag_len =  (10*(to_tag[0]-'0'))+((to_tag[1]-'0'));

            // move to_tag pointer
            to_tag = to_tag + 3;
            // copy the to_tag
            memcpy(msg_sf->to_tag, to_tag, to_tag_len);
            msg_sf->from_tag[to_tag_len+1] = '\0';
        }
    }
    return msg_sf;
}

/**
   NCGP dissector

   Copyright (C) 2016-2024 Michele Campus <michelecampus5@gmail.com>

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
    const char *p = (char*) payload;

    // Fake msg SIP
    struct msg_fake_sip *msg_sf = NULL;
    // pointer to beginning of sdp payload
    const char *sdp = NULL;
    // pointer for call-id
    const char *call_id = NULL;
    // pointer for anumber
    const char *a_number = NULL;
    // pointer for bnumber
    const char *b_number = NULL;
    // pointer for from-tag
    const char *from_tag = NULL;
    // pointer for to-tag
    const char *to_tag = NULL;
    // pointer for command type
    const char *comm = NULL;
    // flag for command type
    int flag = 0;
    // counter
    int cnt = 0;

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
        //fprintf(stderr, "Only OFFER, ANSWER or DELETE command are supported - abort!\n");
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

        // cookie length
        const char *pp = p;
        char *ck = strchr(pp, ' ');
        // count the len
        cnt = ck - pp;

        // copy the magic cookie
        memcpy(msg_sf->magic, p, cnt);
        msg_sf->magic[cnt] = '\0';

        // copy the sdp payload
        memcpy(msg_sf->raw_sdp, sdp, sdp_len);
        msg_sf->raw_sdp[sdp_len] = '\0';


        /**
        *** A-NUMBER ***
        */
        // check if anumber is present
        if((a_number = strstr((const char *)payload, "anumber")) == NULL)
        {
            fprintf(stderr, "error in check NGCP: no A-NUMBER found\n");
            return NULL;
        }
        // move anumber pointer
        a_number = a_number + 7;

        // anumber length
        uint16_t a_number_len = 0;
        char *a = strchr(a_number, ':');
        // count the len
        cnt = a - a_number;

        if(cnt == 1)
            a_number_len = a_number[0]-'0';
        else if(cnt == 2)
            a_number_len = (10*(a_number[0]-'0'))+((a_number[1]-'0'));
        else if(cnt == 3)
            a_number_len = (100*(a_number[0]-'0'))+(10*(a_number[1]-'0'))+(a_number[2]-'0');

        // move a_number pointer
        a_number = a_number + cnt + 1; // +1 for the ':'
        // copy the a_numner
        memcpy(msg_sf->a_number, a_number, a_number_len);
        msg_sf->a_number[a_number_len] = '\0';

        /**
        *** B-NUMBER ***
        */
        // check if anumber is present
        if((b_number = strstr((const char *)payload, "bnumber")) == NULL)
        {
            fprintf(stderr, "error in check NGCP: no B-NUMBER found\n");
            return NULL;
        }
        // move bnumber pointer
        b_number = b_number + 7;

        // bnumber length
        uint16_t b_number_len = 0;
        // count the len
        char *b = strchr(b_number, ':');
        cnt = b - b_number;

        if(cnt == 1)
            b_number_len = b_number[0]-'0';
        else if(cnt == 2)
            b_number_len = (10*(b_number[0]-'0'))+((b_number[1]-'0'));
        else if(cnt == 3)
            b_number_len = (100*(b_number[0]-'0'))+(10*(b_number[1]-'0'))+(b_number[2]-'0');

        // move a_number pointer
        b_number = b_number + cnt + 1; // +1 for the ':'
        // copy the a_numner
        memcpy(msg_sf->b_number, b_number, b_number_len);
        msg_sf->b_number[b_number_len] = '\0';

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
        msg_sf->call_id[call_id_len] = '\0';

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
        uint16_t from_tag_len = 0;
        // count the len
        char *c = strchr(from_tag, ':');
        cnt = c - from_tag;

        if(cnt == 1)
            from_tag_len = from_tag[0]-'0';
        else if(cnt == 2)
            from_tag_len = (10*(from_tag[0]-'0'))+((from_tag[1]-'0'));
        else if(cnt == 3)
            from_tag_len = (100*(from_tag[0]-'0'))+(10*(from_tag[1]-'0'))+(from_tag[2]-'0');

        // move from_tag pointer
        from_tag = from_tag + cnt + 1;
        // copy the from_tag
        memcpy(msg_sf->from_tag, from_tag, from_tag_len);
        msg_sf->from_tag[from_tag_len] = '\0';

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
            uint16_t to_tag_len = 0;
            int cnt = 0;
            char *c = strchr(to_tag, ':');
            cnt = c - to_tag;

            if(cnt == 1)
                to_tag_len = to_tag[0]-'0';
            else if(cnt == 2)
                to_tag_len = (10*(to_tag[0]-'0'))+((to_tag[1]-'0'));
            else if(cnt == 3)
                to_tag_len = (100*(to_tag[0]-'0'))+(10*(to_tag[1]-'0'))+(to_tag[2]-'0');

            // move to_tag pointer
            to_tag = to_tag + cnt + 1;
            // copy the to_tag
            memcpy(msg_sf->to_tag, to_tag, to_tag_len);
            msg_sf->to_tag[to_tag_len] = '\0';
        }
    }
    return msg_sf;
}

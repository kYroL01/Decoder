/**
   RTCP-XR dissector

   decoder -
   Copyright (C) 2016-2017 Michele Campus <fci1908@gmail.com>

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
#include <arpa/inet.h>
#include <byteswap.h>
#include "rtcpxr.h"

// Check packet
int check_rtcpxr_version(const u_char *packet, int size_payload)
{
    u_int8_t offset = 0, is_xr = 0;

    // check param
    if(!packet || size_payload == 0) return -1;

    // pointer used to move through the pkt
    const u_int8_t *pp = packet;

    // cast to rtcp header
    struct rtcp_header_t *rtcp = (struct rtcp_header_t *) packet;

    // check RTCP version
    if(rtcp->version != 2)
    {
        //LERR("wrong version\n");
        return -2;
    }
    // check RTCP type
    if(rtcp->pkt_type < RTCP_SR && rtcp->pkt_type > RTCP_SDES) {
        return -3;
    }

    while(offset < size_payload && is_xr == 0) {
        // get pkt->type SR or RR
        switch(rtcp->pkt_type) {

        case RTCP_SR:
        case RTCP_RR:
        case RTCP_SDES:
            offset = 4*(rtcp_header_get_length(rtcp)+1);
            pp = pp + offset;
            rtcp = (struct rtcp_header_t *) pp;
            break;
        case RTCP_XR:
            is_xr = 1;
            break;
        }
    }

    if(is_xr == 1) return 1; // OK
    return -4; // ERROR
}


// Parse packet and fill JSON buffer
int rtcpxr_dissector(const u_char *packet, int size_payload, char *json_buffer, int buffer_len)
{
    u_int8_t offset = 0, is_xr = 0;
    char text[500] = {0};  // for corr_id
    int corr_id_len;  // for corr_id
    int ret = 0;

    // check param
    if(packet == NULL || size_payload == 0) return -1;

    // pointer used to move through the pkt
    const u_int8_t *pp = packet;

    struct rtcp_header_t *rtcp = (struct rtcp_header_t *) packet;

    while(offset < size_payload && is_xr == 0) {
        // get pkt->type SR or RR
        switch(rtcp->pkt_type) {

        case RTCP_SR:
            offset = 4*(rtcp_header_get_length(rtcp)+1);
            pp = pp + offset;
            rtcp = (struct rtcp_header_t *) pp;
            break;

        case RTCP_RR:
            offset = 4*(rtcp_header_get_length(rtcp)+1);
            pp = pp + offset;
            rtcp = (struct rtcp_header_t *) pp;
            break;

        case RTCP_SDES:
            offset = 4*(rtcp_header_get_length(rtcp)+1);
            const u_int8_t *pp_2 = pp;
            pp_2 = pp_2 + RTCP_HEADER_LEN + 4;

            if(pp_2[0] == 0x01) { // CNAME
                pp_2 = pp_2 + 1;
                corr_id_len = pp_2[0];
                pp_2 = pp_2 + 1;
                memcpy(text, pp_2, corr_id_len);
                printf("corr_id = %s\n", text);
            }
            pp = pp + offset;
            rtcp = (struct rtcp_header_t *) pp;
            break;

            // Extended report
        case RTCP_XR:

            is_xr = 1;

            // create json buffer
            ret += snprintf(json_buffer, buffer_len, "{ ");

            // cast the packet to rtcp-xr
            struct rtcp_xr_t *rtcp_xr = (struct rtcp_xr_t *) pp;

            // start to parse field and create json array
            ret += snprintf(json_buffer + ret, buffer_len - ret, EXTENDED_REPORT_JSON,
                            rtcp_header_get_id(&rtcp_xr->block),
                            rtcp_header_get_loss(&rtcp_xr->block),
                            rtcp_header_discard(&rtcp_xr->block),
                            rtcp_header_burst_rate(&rtcp_xr->block),
                            rtcp_header_gap_rate(&rtcp_xr->block),
                            rtcp_header_burst_duration(&rtcp_xr->block),
                            rtcp_header_gap_duration(&rtcp_xr->block),
                            rtcp_header_round_trip_del(&rtcp_xr->block),
                            rtcp_header_end_sys_delay(&rtcp_xr->block),
                            rtcp_header_signal_lev(&rtcp_xr->block),
                            rtcp_header_noise_lev(&rtcp_xr->block),
                            rtcp_header_RERL(&rtcp_xr->block),
                            rtcp_header_Gmin(&rtcp_xr->block),
                            rtcp_header_Rfact(&rtcp_xr->block),
                            rtcp_header_ext_Rfact(&rtcp_xr->block),
                            rtcp_header_MOS_LQ(&rtcp_xr->block),
                            rtcp_header_MOS_CQ(&rtcp_xr->block),
                            rtcp_header_PLC(&rtcp_xr->block),
                            rtcp_header_JB_adapt(&rtcp_xr->block),
                            rtcp_header_JB_rate(&rtcp_xr->block),
                            rtcp_header_JB_nom(&rtcp_xr->block),
                            rtcp_header_JB_max(&rtcp_xr->block),
                            rtcp_header_JB_abs_max(&rtcp_xr->block));
            break;
        }
    }

    ret += snprintf(json_buffer + ret - 1, buffer_len - ret + 1, "}");

    return 1;
}

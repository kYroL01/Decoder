/**
   RTCP protocol

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
#include <byteswap.h>
#include "rtcp.h"

int check_rtcp_version (char *packet, int len) {

	if(packet == NULL || len == 0) return -1;

	rtcp_header_t *rtcp = (rtcp_header_t *)packet;

	if(rtcp->version != 2)
	{
        fprintf(stderr, "wrong version\n");
		return -2;
	}

	if(rtcp->type < RTCP_SR && rtcp->type > RTCP_XR) {
		return -3;
	}

	return 1;
}


int rtcp_parser(char *packet, int len, char *json_buffer, int buffer_len) {

	if(packet == NULL || len == 0) return -1;

	rtcp_header_t *rtcp = (rtcp_header_t *)packet;
	int ret = 0, is_xr = 0;
	char *rptr;

    // build the JSON buffer
	ret += snprintf(json_buffer, buffer_len, "{ ");

	int pno = 0, total = len;
	while(rtcp) {

		pno++;

        switch(rtcp->type) {

        case RTCP_SR: {
            /* SR, sender report */
            /* LDEBUG("#%d SR (200)\n", pno); */
            printf("#%d SR (200)\n", pno);
            rtcp_sr_t *sr = (rtcp_sr_t*)rtcp;

            ret += snprintf(json_buffer + ret, buffer_len - ret, SENDER_REPORT_JSON,
                            sender_info_get_ntp_timestamp_msw(&sr->si),
                            sender_info_get_ntp_timestamp_lsw(&sr->si),
                            sender_info_get_octet_count(&sr->si),
                            sender_info_get_rtp_timestamp(&sr->si),
                            sender_info_get_packet_count(&sr->si));

            if(sr->header.rc > 0) {

                ret += snprintf(json_buffer + ret, buffer_len - ret, REPORT_BLOCK_JSON,
								ntohl(sr->ssrc), rtcp->type,
								report_block_get_ssrc(&sr->rb[0]),
								report_block_get_high_ext_seq(&sr->rb[0]),
								report_block_get_fraction_lost(&sr->rb[0]),
								report_block_get_interarrival_jitter(&sr->rb[0]),
								report_block_get_cum_packet_loss(&sr->rb[0]),
								report_block_get_last_SR_time(&sr->rb[0]),
								report_block_get_last_SR_delay(&sr->rb[0]));
            }


            break;
        }

        case RTCP_RR: {
            /* RR, receiver report */
            /* LDEBUG("#%d RR (201)\n", pno); */
            printf("#%d RR (201)\n", pno);
            rtcp_rr_t *rr = (rtcp_rr_t*)rtcp;

            if(rr->header.rc > 0) {

                ret += snprintf(json_buffer+ret, buffer_len - ret, REPORT_BLOCK_JSON,
								ntohl(rr->ssrc), rtcp->type,
								report_block_get_ssrc(&rr->rb[0]),
								report_block_get_high_ext_seq(&rr->rb[0]),
								report_block_get_fraction_lost(&rr->rb[0]),
								report_block_get_interarrival_jitter(&rr->rb[0]),
								report_block_get_cum_packet_loss(&rr->rb[0]),
								report_block_get_last_SR_time(&rr->rb[0]),
								report_block_get_last_SR_delay(&rr->rb[0]));
            }
            break;
        }

        case RTCP_SDES: {
            /* LDEBUG("#%d SDES (202)\n", pno); */
            printf("#%d SDES (202)\n", pno);

            /* if not needed send sdes */
            /* if(!send_sdes) break; */

            rtcp_sdes_t *sdes = (rtcp_sdes_t*)rtcp;

            rptr = rtcp + 2;

            int sdes_report_count = 0;

            char *end = (char*) rptr + (4*(rtcp_header_get_length(&sdes->header) + 1) -15);

            ret += snprintf(json_buffer+ret, buffer_len - ret, SDES_REPORT_BEGIN_JSON, ntohl(sdes->ssrc), sdes_chunk_get_csrc(&sdes->chunk));

            while(rptr < end) {

                if (rptr+2<=end) {

                    uint8_t chunk_type = rptr[0];
                    uint8_t chunk_len = rptr[1];

                    if(chunk_len == 0) break;

                    rptr += 2;

                    ret += snprintf(json_buffer+ret, buffer_len - ret, SDES_REPORT_INFO_JSON, chunk_type, chunk_len, rptr);

                    sdes_report_count++;

                    if (rptr+chunk_len<=end) rptr+=chunk_len;
                    else break;
                }
                else {
                    break;
                }
            }

            /* cut , off */
            ret -= 1;

            ret += snprintf(json_buffer + ret, buffer_len - ret, SDES_REPORT_END_JSON, sdes_report_count);

            break;
        }

        case RTCP_XR: {
            /* LDEBUG("#%d XR (207)\n", pno); */
            printf("#%d XR (207)\n", pno);

            // set flag
            is_xr = 1;

            // cast the packet to rtcp-xr
            struct rtcp_xr_t *rtcp_xr = (struct rtcp_xr_t *) rtcp;

            // start to parse field and create json array
            ret += snprintf(json_buffer + ret, buffer_len - ret, EXTENDED_REPORT_JSON,
                            rtcpxr_header_get_type(&rtcp_xr->xr_header),
                            rtcpxr_header_get_id(&rtcp_xr->block),
                            rtcpxr_header_get_loss(&rtcp_xr->block),
                            rtcpxr_header_discard(&rtcp_xr->block),
                            rtcpxr_header_burst_rate(&rtcp_xr->block),
                            rtcpxr_header_gap_rate(&rtcp_xr->block),
                            rtcpxr_header_burst_duration(&rtcp_xr->block),
                            rtcpxr_header_gap_duration(&rtcp_xr->block),
                            rtcpxr_header_round_trip_del(&rtcp_xr->block),
                            rtcpxr_header_end_sys_delay(&rtcp_xr->block),
                            rtcpxr_header_signal_lev(&rtcp_xr->block),
                            rtcpxr_header_noise_lev(&rtcp_xr->block),
                            rtcpxr_header_RERL(&rtcp_xr->block),
                            rtcpxr_header_Gmin(&rtcp_xr->block),
                            rtcpxr_header_Rfact(&rtcp_xr->block),
                            rtcpxr_header_ext_Rfact(&rtcp_xr->block),
                            rtcpxr_header_MOS_LQ(&rtcp_xr->block),
                            rtcpxr_header_MOS_CQ(&rtcp_xr->block),
                            rtcpxr_header_PLC(&rtcp_xr->block),
                            rtcpxr_header_JB_adapt(&rtcp_xr->block),
                            rtcpxr_header_JB_rate(&rtcp_xr->block),
                            rtcpxr_header_JB_nom(&rtcp_xr->block),
                            rtcpxr_header_JB_max(&rtcp_xr->block),
                            rtcpxr_header_JB_abs_max(&rtcp_xr->block));

            /* ret -= 1; */
            ret += snprintf(json_buffer+ret-1, buffer_len-ret+1, "}");

            break;
        }

        case RTCP_BYE: {
            printf("\n#%d GOODBYE (203)\n", pno);
            /* ret = 0; */
            //rtcp_bye_t *bye = (rtcp_bye_t*)rtcp;
            break;
        }
        case RTCP_APP: {
            printf("\n#%d APP (204)\n", pno);
            //rtcp_app_t *app = (rtcp_app_t*)rtcp;
            break;
        }
        default:
            break;
		}

        int length = ntohs(rtcp->length);
        if(length == 0) {
            break;
        }

        total -= length*4+4;
        if(total <= 0) {
            /* LDEBUG("End of RTCP packet\n"); */
            printf("End of RTCP packet\n");
            break;
        }
        rtcp = (rtcp_header_t *)((uint32_t*)rtcp + (length + 1));
    }

    /* bad parsed message */
    if(ret < 10) return 0;

    ret += snprintf(json_buffer+ret-1, buffer_len-ret+1, "}");

    if(is_xr == 1) printf("RTCP-XR packet\n");

	return ret;
}

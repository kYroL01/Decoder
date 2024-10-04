/**
   RTP dissector

   Copyright (C) 2016-2024 Michele Campus <michelecampus5@gmail.com>

   This file is part of decoder.

   [ The headers in this module follow the RFC 1889
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
#include "rtp.h"

void print_info_rtp(rtp_header_t *rtp, unsigned int ts, unsigned int ssrc) {

    printf("RTP pkt::\n");
    printf("\t Version = %d\n", rtp->version);
    printf("\t Padding = %d\n", rtp->p);
    printf("\t eXtension = %d\n", rtp->x);
    printf("\t CSRC count = %d\n", rtp->cc);
    printf("\t Marker = %d\n", rtp->m);
    printf("\t Payload Type = %d\n", rtp->pt);
    printf("\t Timestamp = %u\n", ts);
    printf("\t SSRC = %u\n\n", ssrc);
}

int check_rtp_version (char *packet, int len) {

	if(packet == NULL || len == 0)
        return -1;

	rtp_header_t *rtp = (rtp_header_t *)packet;

	if(rtp->version != 2)
	{
        fprintf(stderr, "wrong version\n");
		return -2;
	}

	return 0;
}


int rtp_parser(char *packet, int len, char *json_buffer, int buffer_len) {

	if(packet == NULL || len == 0)
        return -1;

	rtp_header_t *rtp = (rtp_header_t *)packet;
	int ret = 0, is_parsed = 0;

    while(rtp && is_parsed == 0) {

        switch(rtp->pt) {
        case 0:
        case 8:
        case 109:{
            printf("RTP Payload Type = PCMU (0)\n");
            unsigned int ts = (rtp->ts[3]) + (rtp->ts[2] << 8) + (rtp->ts[1] << 16) + (rtp->ts[0] << 24);
            unsigned int ssrc = (rtp->ssrc[3]) + (rtp->ssrc[2] << 8) + (rtp->ssrc[1] << 16) + (rtp->ssrc[0] << 24);
            // Pint Info
            print_info_rtp(rtp, ts, ssrc);
            is_parsed = 1;
            ret = 0;
            break;
        }
        default:
            ret = -1;
            is_parsed = 1;
            break;
		}
    }
  	return ret;
}

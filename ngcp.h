/**
   Header file for ncgp parser

   Copyright (C) 2016-2019 Michele Campus <michelecampus5@gmail.com>

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
#ifndef NGCP_H_
#define NGCP_H_

#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <net/ethernet.h>

#define OFFER  1
#define ANSWER 2
#define DELETE 3

#ifdef __GNUC__
/* GNU C */
#define PACK_OFF __attribute__ ((__packed__));
#endif

struct msg_fake_sip {
  char magic[13];
  char *raw_sdp;
  char call_id[256];
  char from_tag[100];
  char to_tag[100];
  int comm_flag; // 1 answer 2 offer 3 delete
};

struct msg_fake_sip *ngcp_parser(const u_char * payload,
                                 const u_int16_t size_payload);

#endif

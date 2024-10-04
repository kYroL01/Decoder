/**
   Header file for RTP protocol

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
#ifndef _RTP_H
#define _RTP_H

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>

#define RTP_HEADER_LEN 4

typedef struct _rtp_header{
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:2;   /* protocol version */
    unsigned int p:1;         /* padding flag */
    unsigned int x:1;         /* header extension flag */
    unsigned int cc:4;        /* CSRC count */
    unsigned int m:1;         /* marker bit */
    unsigned int pt:7;        /* payload type */
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int cc:4;        /* CSRC count */
    unsigned int x:1;         /* header extension flag */
    unsigned int p:1;         /* padding flag */
    unsigned int version:2;   /* protocol version */
    unsigned int pt:7;        /* payload type */
    unsigned int m:1;         /* marker bit */
#else
#error Define one of __BYTE_ORDER
#endif
    unsigned int seq:16;      /* sequence number */
    uint8_t ts[4];            /* timestamp */
    uint8_t ssrc[4];          /* synchronization source */
} rtp_header_t;


#endif /* _RTP_H*/

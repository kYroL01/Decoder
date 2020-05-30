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
#ifndef MSRP_H
#define MSRP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <byteswap.h>
#include <endian.h>
#include <time.h>

/* Definition of MSRP common info JSON */
#define MSRP_HEADER_JSON "\"msrp_info\": { [\"class\":\"%s\",\"type\":\"%s\",\"command\":\"%s\",\"app-ID\":%d] }"

#define JSON_BUFFER_LEN 5000

#define LEN 300


// MSRP SEND pkt
struct msrp_send_t
{
    char transaction_ID[LEN];
    char method[LEN];

    char to_path[LEN];
    char from_path[LEN];
    char message_ID[LEN];
    char succ_repo[LEN];
    char byte[LEN];
    char content_type[LEN];

    char status[LEN];
    
};


// MSRP REPORT pkt
struct msrp_report_t
{
    char transaction_ID[LEN];
    char method[LEN];

    char to_path[LEN];
    char from_path[LEN];
    char message_ID[LEN];
    char status[LEN];

    char end_line[LEN];
};

// MSRP answer pkt
struct msrp_answer_t
{
    char transaction_ID[LEN];
    char method[LEN];

    char to_path[LEN];
    char from_path[LEN];

    char end_line[LEN];
};

#endif

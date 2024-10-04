/**
   Prototypes of utility function for decoder

   Copyright (C) 2016-2024 Michele Campus <michelecampus5@gmail.com>

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
#ifndef FUNCTIONS_H_
#define FUNCTIONS_H_

#include <pcap.h>
#include <signal.h>
#include "structures.h"
#include "tls_ssl.h"
#include "diameter.h"
#include "rtcp.h"
#include "ngcp.h"
#include "rtsp.h"
#include "gtp.h"

/* global variable to represent SIGINT signal */
extern volatile sig_atomic_t signal_flag;

/** Get the pcap error occurred */
inline static void pcap_fatal(const char *err_name, ...)
{
    fprintf(stderr, "Fatal Error in %s \n", err_name);
}

/** Protocol callback function call in pcap_loop */
void callback_proto(u_char *, const struct pcap_pkthdr *, const u_char *);

/** Init data flow struct */
struct flow_callback_proto *flow_callback_proto_init(pcap_t *, u_int8_t);

/** Print statistics */
void print_stats(struct flow_callback_proto *);

/** Functions for the HASH TABLE (uthash) **/
// FIND FLOW BY KEY
struct Hash_Table * find_flow_by_key(struct Flow_key *key);
// DELETE FLOW BY KEY
void delete_flow_by_key(struct Flow_key *key);
// DELETE ALL FLOWS
void delete_all_Flows();

/** ##### ##### ##### PROTOCOL FUNCTIONS ##### ##### ##### */

/**
   Function for TLS dissection
**/
int tls_parser(const u_char ** payload,
               const u_int16_t size_payload,
               const u_int8_t ip_version,
               struct Flow_key * flow_key,
               const u_int16_t src_port,
               const u_int16_t dst_port,
               const u_int8_t proto_id_l3,
               u_int8_t s
               /* struct Hash_Table ** HT_Flows */);
/**
   Functions for RTP dissection
**/
// Check version
int check_rtp_version(const u_char *packet, int size_payload);
// Dissect packet
int rtp_parser(const u_char *packet,
               int size_payload,
               char *json_buffer,
               int buffer_len);
/**
   Functions for RTCP dissection
**/
int check_rtcp_version(const u_char *packet, int size_payload);
int rtcp_parser(const u_char *packet,
                int size_payload,
                char *json_buffer,
                int buffer_len);

/**
   Functions for DIAMETER dissection
**/

int diameter_parser(const u_char *packet,
                    int size_payload,
                    char *json_buffer,
                    int buffer_len);
/**
   Functions for NGCP dissection
**/
struct msg_fake_sip * ngcp_parser(const u_char * payload, const u_int16_t size_payload);
/**
   Functions for RTSP dissection
**/
int rtsp_parser(const u_char *packet, int size_payload, char *json_buffer, int buffer_len);

/**
   Functions for the GTP dissection
**/
// Parse packet, check if it's GTP and create JSON buffer with protocol information
int gtp_parser(const unsigned char *packet, int size_payload,  const u_int16_t src_port,
               const u_int16_t dst_port, char *json_buffer, int buffer_len);

/**
   hash function for integer number
   thanks to https://stackoverflow.com/a/12996028/859453
*/
/* unsigned int hash_ID(unsigned int ID) */
/* { */
/*     ID = ((ID >> 16) ^ ID) * 0x45d9f3b; */
/*     ID = ((ID >> 16) ^ ID) * 0x45d9f3b; */
/*     ID = (ID >> 16) ^ ID; */
/*     return ID; */
/* } */

#endif

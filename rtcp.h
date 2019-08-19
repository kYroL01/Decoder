/**
   Header containing macors and struct for rtcp protocol

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
#ifndef _RTCP_H
#define _RTCP_H

#include <arpa/inet.h>
#include <endian.h>
#include <inttypes.h>
#include <string.h>

#define SENDER_REPORT_JSON "\"sender_information\":{\"ntp_timestamp_sec\":%u,\"ntp_timestamp_usec\":%u,\"octets\":%u,\"rtp_timestamp\":%u, \"packets\":%u},"
#define REPORT_BLOCK_JSON "\"ssrc\":%u,\"type\":%u, \"report_blocks\":[{\"source_ssrc\":%u,\"highest_seq_no\":%u,\"fraction_lost\":%u,\"ia_jitter\":%u,\
\"packets_lost\":%u,\"lsr\":%u,\"dlsr\":%u}],\"report_count\":1,"

#define SDES_REPORT_BEGIN_JSON "\"sdes_ssrc\":%u,\"sdes_chunk_ssrc\":%u,\"sdes_information\": [ "
#define SDES_REPORT_INFO_JSON "{\"type\":%u,\"text\":\"%.*s\"},"
#define SDES_REPORT_END_JSON "],\"sdes_report_count\":%u,"

#define EXTENDED_REPORT_JSON "\"extended_report_information\":{\"type\":%u, \"identifier\":%u, \"loss_rate\":%u, \"discard_rate\":%u, \"burst_rate\":%u, \"gap_rate\":%u, \"burst_duration\":%u, \"gap_duration\":%u, \"round_trip_delay\":%u, \"end_sys_delay\":%u, \"signal_lev\":%u, \"noise_lev\":%u, \"RERL\":%u, \"Gmin\":%u, \"R_fact\":%u, \"ext_R_fact\":%u, \"MOS_LQ\":%u, \"MOS_CQ\":%u, \"RX_conf\":[{\"PLC\":%u, \"JB_adapt\":%u, \"JB_rate\":%u}], \"JB_nom\":%u, \"JB_max\":%u, \"JB_abs_max\":%u}"

extern int send_sdes;

typedef enum {
    RTCP_SR   = 200,
    RTCP_RR   = 201,
    RTCP_SDES = 202,
    RTCP_BYE  = 203,
    RTCP_APP  = 204,
    RTCP_XR   = 207
} rtcp_type_t;

#define RTCP_HEADER_LEN 4
typedef struct _rtcp_header
{
    #if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t rc:5;
	uint16_t type:8;
    #elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rc:5;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:8;
    #endif
	uint16_t length:16;
} rtcp_header_t;

#define rtcp_header_get_length(ch) ntohs((ch)->length)

typedef struct _sender_info
{
	uint32_t ntp_timestamp_msw;
	uint32_t ntp_timestamp_lsw;
	uint32_t rtp_timestamp;
	uint32_t senders_packet_count;
	uint32_t senders_octet_count;
} sender_info_t;

#define sender_info_get_ntp_timestamp_msw(si) ((si)->ntp_timestamp_msw)
#define sender_info_get_ntp_timestamp_lsw(si) ((si)->ntp_timestamp_lsw)
#define sender_info_get_rtp_timestamp(si) ((si)->rtp_timestamp)
#define sender_info_get_packet_count(si) ntohl((si)->senders_packet_count)
#define sender_info_get_octet_count(si) ntohl((si)->senders_octet_count)

/*! \brief RTCP Report Block (http://tools.ietf.org/html/rfc3550#section-6.4.1) */
typedef struct _report_block
{
	uint32_t ssrc;
	uint32_t fl_cnpl;
	uint32_t ext_high_seq_num_rec;
	uint32_t interarrival_jitter;
	uint32_t lsr;
	uint32_t delay_snc_last_sr;
} report_block_t;

#define report_block_get_ssrc(rb) ntohl((rb)->ssrc)
#define report_block_get_fraction_lost(rb) (((uint32_t)ntohl((rb)->fl_cnpl))>>24)
#define report_block_get_cum_packet_loss(rb) (((uint32_t)ntohl((rb)->fl_cnpl)) & 0xFFFFFF)
#define report_block_get_high_ext_seq(rb) ntohl(((report_block_t*)(rb))->ext_high_seq_num_rec)
#define report_block_get_interarrival_jitter(rb) ntohl(((report_block_t*)(rb))->interarrival_jitter)
#define report_block_get_last_SR_time(rb) ntohl(((report_block_t*)(rb))->lsr)
#define report_block_get_last_SR_delay(rb) ntohl(((report_block_t*)(rb))->delay_snc_last_sr)

typedef struct _rtcp_sr
{
	rtcp_header_t header;
	uint32_t ssrc;
	sender_info_t si;
	report_block_t rb[1];
} rtcp_sr_t;

typedef struct _rtcp_rr
{
	rtcp_header_t header;
	uint32_t ssrc;
	report_block_t rb[1];
} rtcp_rr_t;

typedef struct _rtcp_sdes_chunk
{
	uint32_t csrc;
} rtcp_sdes_chunk_t;

typedef struct _rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
	char content[1];
} rtcp_sdes_item_t;

typedef struct _rtcp_sdes_t
{
	rtcp_header_t header;
	uint32_t ssrc;
	rtcp_sdes_chunk_t chunk;
	rtcp_sdes_item_t item;
} rtcp_sdes_t;

typedef struct _rtcp_bye
{
	rtcp_header_t header;
	uint32_t ssrc[1];
} rtcp_bye_t;

typedef struct _rtcp_app
{
	rtcp_header_t header;
	uint32_t ssrc;
	char name[4];
} rtcp_app_t;

#define sdes_chunk_get_csrc(c)  ntohl((c)->csrc)
#define sdes_chunk_item_get_len(item)  (item)->len
#define sdes_chunk_item_get_type(item) (item)->type

// RTCP-XR header
struct rtcp_xr_header_t
{
    u_int8_t type;
    u_int8_t spec_type;
    u_int16_t len;
};

// RTCP-XR information block
struct rtcp_xr_block_t
{
    uint32_t id;
    uint8_t loss_rate;
    uint8_t discard_rate;
    uint8_t burst_rate;
    uint8_t gap_rate;
    uint16_t burst_duration;
    uint16_t gap_duration;
    uint16_t round_trip_delay;
    uint16_t end_sys_delay;
    uint8_t signal_lev;
    uint8_t noise_lev;
    uint8_t RERL;
    uint8_t Gmin;
    uint8_t R_fact;
    uint8_t ext_R_fact;
    uint8_t MOS_LQ;
    uint8_t MOS_CQ;
    #if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t PLC:2;
    uint8_t JB_adapt:2;
    uint8_t JB_rate:4;
    #elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t JB_rate:4;
    uint8_t JB_adapt:2;
    uint8_t PLC:2;
    #endif
    uint8_t RESERVED;
    uint16_t JB_nom;
    uint16_t JB_max;
    uint16_t JB_abs_max;
};

// RTCP-XR packet
struct rtcp_xr_t
{
    rtcp_header_t header;
    u_int32_t ssrc;
    struct rtcp_xr_header_t xr_header;
    struct rtcp_xr_block_t block;
};


// Macros to get information from the XR block
#define rtcpxr_header_get_type(xr)         (xr)->type
#define rtcpxr_header_get_id(xr)           ntohl((xr)->id)
#define rtcpxr_header_get_loss(xr)         (xr)->loss_rate
#define rtcpxr_header_discard(xr)          (xr)->discard_rate
#define rtcpxr_header_burst_rate(xr)       (xr)->burst_rate
#define rtcpxr_header_gap_rate(xr)         (xr)->gap_rate
#define rtcpxr_header_burst_duration(xr)   (xr)->burst_duration
#define rtcpxr_header_gap_duration(xr)     (xr)->gap_duration
#define rtcpxr_header_round_trip_del(xr)   ntohs((xr)->round_trip_delay)
#define rtcpxr_header_end_sys_delay(xr)    ntohs((xr)->end_sys_delay)
#define rtcpxr_header_signal_lev(xr)       (xr)->signal_lev
#define rtcpxr_header_noise_lev(xr)        (xr)->noise_lev
#define rtcpxr_header_RERL(xr)             (xr)->RERL
#define rtcpxr_header_Gmin(xr)             (xr)->Gmin
#define rtcpxr_header_Rfact(xr)            (xr)->R_fact
#define rtcpxr_header_ext_Rfact(xr)        (xr)->ext_R_fact
#define rtcpxr_header_MOS_LQ(xr)           (xr)->MOS_LQ
#define rtcpxr_header_MOS_CQ(xr)           (xr)->MOS_CQ
#define rtcpxr_header_PLC(xr)              (xr)->PLC
#define rtcpxr_header_JB_adapt(xr)         (xr)->JB_adapt
#define rtcpxr_header_JB_rate(xr)          (xr)->JB_rate
#define rtcpxr_header_JB_nom(xr)           ntohs((xr)->JB_nom)
#define rtcpxr_header_JB_max(xr)           ntohs((xr)->JB_max)
#define rtcpxr_header_JB_abs_max(xr)       ntohs((xr)->JB_abs_max)

#endif /* _RTCP_H*/

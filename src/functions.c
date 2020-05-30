/**
   Implementation of functions.h

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include "functions.h"
#include "structures.h"
#include "uthash.h"

#define JSON_BUFFER_LEN 5000

/* ### Declaration of HASH TABLE ### */
extern struct Hash_Table *HT_Flows;

/* get the pcap error occurred */
extern inline void pcap_fatal(const char *, ...);

/**
   #param uint16_t
   #param int
   #param int
   @return n bit from position p of number x
**/
static inline uint8_t getBits(uint16_t x, int p, int n)
{
    return (x >> (p+1-n)) & ~(~0 << n);
}

/**
   Init data flow struct
**/
struct flow_callback_proto *flow_callback_proto_init(pcap_t * p_handle, u_int8_t save)
{
    struct flow_callback_proto *flow = malloc(sizeof(struct flow_callback_proto));
    if(!flow) perror("flow malloc failed");

    flow->pcap_handle = p_handle;
    flow->save = save;

    return flow;
}

/**
   Print IPv4 address 
**/
void print_ipv4(u_int32_t addr)
{
    unsigned char bytes[4];
    bytes[0] = addr & 0xFF;
    bytes[1] = (addr >> 8) & 0xFF;
    bytes[2] = (addr >> 16) & 0xFF;
    bytes[3] = (addr >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
}

/**
   Print IPv6 address 
**/
void print_ipv6(const struct ipv6_addr * addr) {

    printf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
           (int)addr->ipv6_addr[0], (int)addr->ipv6_addr[1],
           (int)addr->ipv6_addr[2], (int)addr->ipv6_addr[3],
           (int)addr->ipv6_addr[4], (int)addr->ipv6_addr[5],
           (int)addr->ipv6_addr[6], (int)addr->ipv6_addr[7],
           (int)addr->ipv6_addr[8], (int)addr->ipv6_addr[9],
           (int)addr->ipv6_addr[10], (int)addr->ipv6_addr[11],
           (int)addr->ipv6_addr[12], (int)addr->ipv6_addr[13],
           (int)addr->ipv6_addr[14], (int)addr->ipv6_addr[15]);
}


/** ### Function for the HASH TABLE (uthash) ### **/

// FIND FLOW BY KEY
struct Hash_Table * find_flow_by_key(struct Flow_key *key)
{
    struct Hash_Table * flow_in;

    // search the flow by a key
    HASH_FIND(hh, HT_Flows, key, sizeof(struct Flow_key), flow_in);

    return flow_in;
}

// DELETE FLOW BY KEY
void delete_flow_by_key(struct Flow_key *key)
{
    struct Hash_Table * flow_in;

    // search the flow by a key
    HASH_FIND(hh, HT_Flows, key, sizeof(struct Flow_key), flow_in);
    if(!flow_in) {
        HASH_DEL(HT_Flows, flow_in);
        free(flow_in);
    }
}

// DELETE ALL FLOWS
void delete_all_Flows()
{
    struct Hash_Table *current_user, *tmp;

    HASH_ITER(hh, HT_Flows, current_user, tmp) {
        HASH_DEL(HT_Flows, current_user);  /* delete it (users advances to next) */
        free(current_user);
    }
}

// PRINT HASH TABLE
void print_HashTable(u_int8_t ip_version)
{
    struct Hash_Table *el;
    int n = 1, f = 1;

    printf("\n###### HASH TABLE ######\n");
    printf("Total flow stored = %d\n", n = HASH_COUNT(HT_Flows));

    if(n > 0) {
        for(el = HT_Flows; el != NULL; el = (struct Hash_Table*)(el->hh.next)) {

            printf("Flow %d: \n", f++);

            printf("\t IP source addr = ");
            if(ip_version == IPv4)
                print_ipv4(el->flow_key_hash.ip_src);
            else
                print_ipv6(&el->flow_key_hash.ipv6_src);

            printf("\t IP dest addr = ");
            if(ip_version == IPv4)
                print_ipv4(el->flow_key_hash.ip_dst);
            else
                print_ipv6(&el->flow_key_hash.ipv6_dst);

            printf("\t SRC PORT = %d\n", el->flow_key_hash.src_port);
            printf("\t DST PORT = %d\n", el->flow_key_hash.dst_port);
        }
    }
}


/**
   Function to process a packet
**/
static unsigned int process_packet(const u_char * payload,
                                   const u_int16_t size_payload,
                                   const u_int8_t ip_version,
                                   const struct ipv4_hdr * iphv4,
                                   const struct ipv6_hdr * iphv6,
                                   const u_int16_t src_port,
                                   const u_int16_t dst_port,
                                   const u_int8_t proto_id_l3,
                                   struct flow_callback_proto * fcp,
                                   u_int8_t save
                                   /* struct Hash_Table * HT_Flows */)
{
    int ret = 0;

    /* ################# */
    /**  UDP Protocols  **/
    /* ################# */
    if(proto_id_l3 == IPPROTO_UDP) {

        /**
           Check NGCP dissector
        */
        struct msg_fake_sip *msg_sf;
        msg_sf = ngcp_parser(payload, size_payload);
        if(msg_sf)
        {
            // print fields
            printf("\033[1;31m");
            printf("\n-------------------- --- ---- --- -------------------- \n");
            printf("-------------------- MSG FAKE SIP -------------------- \n");
            printf("\033[0m");
            printf("comand type [1 OFFER 2 ANSWER 3 DELETE]: %d\n", msg_sf->comm_flag);
            printf("\033[0;32m");
            printf("magic cookie: %s\n", msg_sf->magic);
            printf("\033[0m");
            printf("\033[0;33m");
            printf("sdp raw: %s\n", msg_sf->raw_sdp);
            printf("\033[0m");
            printf("\033[0;36m");
            printf("from-tag: %s\n", msg_sf->from_tag);
            printf("\033[0;36m");
            printf("\033[0;35m");
            printf("to-tag: %s\n", msg_sf->to_tag);
            printf("\033[0m");
            printf("\033[1;31m");
            printf("\n-------------------- --- ---- --- -------------------- \n");
            printf("\n-------------------- --- ---- --- -------------------- \n");
            printf("\033[0m");
            ret = 2;
            goto end;
        }

        /**
           Check RTCP dissector
        */
        ret = check_rtcp_version(payload, size_payload);

        if(ret == -1) {
            fprintf(stderr, "error on check rtcp_version: bad params\n");
            return ret;
        }
        else if(ret == -2) {
            fprintf(stderr, "error on check rtcp_version: bad version\n");
            return ret;
        }
        else if(ret == -3) {
            fprintf(stderr, "error on check rtcp_version: bad pkt type\n");
            return ret;
        }

        char* json_buffer = malloc(sizeof(char) * JSON_BUFFER_LEN);

        // dissect
        ret = rtcp_parser(payload,
                          size_payload,
                          json_buffer,
                          JSON_BUFFER_LEN);
        if(ret == -1)
            fprintf(stderr, "error on rtcp_dissector\n");

        printf("\nRTCP protocol FOUND ->\n");
        /* Print JSON buffer */
        if(ret > 0)
            printf("%s\n\n", json_buffer);

        /* free json_buffer */
        free(json_buffer);

        // return code for RTCP
        ret = 1;
    }

    /* ################# */
    /**  TCP Protocols  **/
    /* ################# */
    else {

        // declare JSON buffer
        char* json_buffer = malloc(sizeof(char) * JSON_BUFFER_LEN);

        /**
           Check RTSP dissector
        */
        memset(json_buffer, 0, JSON_BUFFER_LEN);

        // Call RTSP dissector function
        ret = rtsp_parser(payload,
                          size_payload,
                          json_buffer,
                          JSON_BUFFER_LEN);
        if(ret == -1) {
            fprintf(stderr, "Not an rtsp packet\n");
        }
        else {
            ret = 5;
            /* Print JSON buffer */
            printf("%s\n", json_buffer);
            goto end;
        }


        /**
           Check TLS dissector
        */
        memset(json_buffer, 0, JSON_BUFFER_LEN);

        struct Flow_key  *flow_key  = NULL;
        struct Handshake *handshake = NULL;

        // check parameters
        if(!payload || size_payload <= 0 ||
           (ip_version != 4 && ip_version != 6) || (!iphv4 && !iphv6) ||
           proto_id_l3 <= 0 || !fcp) {
            fprintf(stderr, "\t Discard packet\n");
            return -1;
        }

        /**
           # KEY #
           define the Flow Key (allocate memory)
           prepare the key with passed values
        */
        flow_key = malloc(sizeof(struct Flow_key));
        memset(flow_key, 0, sizeof(struct Flow_key));

        // fill the Flow Key
        if(ip_version == IPv4) {
            flow_key->ip_src = iphv4->ip_src_addr; // src address
            flow_key->ip_dst = iphv4->ip_dst_addr; // dst address
        }
        else {
            // src address
            flow_key->ipv6_src.ipv6_addr[0] = iphv6->ipv6_src.ipv6_addr[0];
            flow_key->ipv6_src.ipv6_addr[1] = iphv6->ipv6_src.ipv6_addr[1];
            flow_key->ipv6_src.ipv6_addr[2] = iphv6->ipv6_src.ipv6_addr[2];
            flow_key->ipv6_src.ipv6_addr[3] = iphv6->ipv6_src.ipv6_addr[3];
            flow_key->ipv6_src.ipv6_addr[4] = iphv6->ipv6_src.ipv6_addr[4];
            flow_key->ipv6_src.ipv6_addr[5] = iphv6->ipv6_src.ipv6_addr[5];
            flow_key->ipv6_src.ipv6_addr[6] = iphv6->ipv6_src.ipv6_addr[6];
            flow_key->ipv6_src.ipv6_addr[7] = iphv6->ipv6_src.ipv6_addr[7];
            flow_key->ipv6_src.ipv6_addr[8] = iphv6->ipv6_src.ipv6_addr[8];
            flow_key->ipv6_src.ipv6_addr[9] = iphv6->ipv6_src.ipv6_addr[9];
            flow_key->ipv6_src.ipv6_addr[10] = iphv6->ipv6_src.ipv6_addr[10];
            flow_key->ipv6_src.ipv6_addr[11] = iphv6->ipv6_src.ipv6_addr[11];
            flow_key->ipv6_src.ipv6_addr[12] = iphv6->ipv6_src.ipv6_addr[12];
            flow_key->ipv6_src.ipv6_addr[13] = iphv6->ipv6_src.ipv6_addr[13];
            flow_key->ipv6_src.ipv6_addr[14] = iphv6->ipv6_src.ipv6_addr[14];
            flow_key->ipv6_src.ipv6_addr[15] = iphv6->ipv6_src.ipv6_addr[15];
            // dst address
            flow_key->ipv6_dst.ipv6_addr[0] = iphv6->ipv6_dst.ipv6_addr[0];
            flow_key->ipv6_dst.ipv6_addr[1] = iphv6->ipv6_dst.ipv6_addr[1];
            flow_key->ipv6_dst.ipv6_addr[2] = iphv6->ipv6_dst.ipv6_addr[2];
            flow_key->ipv6_dst.ipv6_addr[3] = iphv6->ipv6_dst.ipv6_addr[3];
            flow_key->ipv6_dst.ipv6_addr[4] = iphv6->ipv6_dst.ipv6_addr[4];
            flow_key->ipv6_dst.ipv6_addr[5] = iphv6->ipv6_dst.ipv6_addr[5];
            flow_key->ipv6_dst.ipv6_addr[6] = iphv6->ipv6_dst.ipv6_addr[6];
            flow_key->ipv6_dst.ipv6_addr[7] = iphv6->ipv6_dst.ipv6_addr[7];
            flow_key->ipv6_dst.ipv6_addr[8] = iphv6->ipv6_dst.ipv6_addr[8];
            flow_key->ipv6_dst.ipv6_addr[9] = iphv6->ipv6_dst.ipv6_addr[9];
            flow_key->ipv6_dst.ipv6_addr[10] = iphv6->ipv6_dst.ipv6_addr[10];
            flow_key->ipv6_dst.ipv6_addr[11] = iphv6->ipv6_dst.ipv6_addr[11];
            flow_key->ipv6_dst.ipv6_addr[12] = iphv6->ipv6_dst.ipv6_addr[12];
            flow_key->ipv6_dst.ipv6_addr[13] = iphv6->ipv6_dst.ipv6_addr[13];
            flow_key->ipv6_dst.ipv6_addr[14] = iphv6->ipv6_dst.ipv6_addr[14];
            flow_key->ipv6_dst.ipv6_addr[15] = iphv6->ipv6_dst.ipv6_addr[15];
        }

        // src port
        flow_key->src_port = src_port;
        // dst port
        flow_key->dst_port = dst_port;

        // proto L3
        flow_key->proto_id_l3 = proto_id_l3;

        /* Call TLS dissector function */
        ret = tls_parser(&payload,
                         size_payload,
                         ip_version,
                         flow_key,
                         src_port,
                         dst_port,
                         proto_id_l3,
                         save);
        /* HT_Flows */
        if(ret == -1) {
            fprintf(stderr, "Not a TLS packet\n");
            // free structs
            free(flow_key);
            free(handshake);
        }
        else {
            ret = 4;
            goto end;
        }


        /**
           Check DIAMETER dissector
        */
        memset(json_buffer, 0, JSON_BUFFER_LEN);

        // Call DIAMETER dissector function
        ret = diameter_parser(payload,
                              size_payload,
                              json_buffer,
                              JSON_BUFFER_LEN);
        if(ret == -1) {
            fprintf(stderr, "Not a diameter packet\n");
        }
        else {
            ret = 3;
            /* Print JSON buffer */
            printf("%s\n", json_buffer);
        }


        /**
           Check MSRP dissector
        */
        memset(json_buffer, 0, JSON_BUFFER_LEN);

        // Call MSRP dissector function
        ret = msrp_parser(payload,
                          size_payload,
                          json_buffer,
                          JSON_BUFFER_LEN);
        if(ret == -1) {
            fprintf(stderr, "Not a diameter packet\n");
        }
        else {
            ret = 0;
            /* Print JSON buffer */
            printf("%s\n", json_buffer);
        }        
    }
 end:
    return ret;
}


// Protocol callback function
void callback_proto(u_char *args, const struct pcap_pkthdr *pkt_header, const u_char *packet) {


    // define flow based on thread_id on call_thread array
    struct flow_callback_proto * fcp = (struct flow_callback_proto*) args;

    // define ethernet header
    const struct ether_hdr *ethernet_header = NULL;
    // define vlan header
    const struct vlan_hdr *vlan_header = NULL;
    // define mpls
    union mpls {
        uint32_t u32;
        struct mpls_header mpls;
    } mpls;
    // define radio_tap header
    const struct radiotap_hdr *radiotap_header = NULL;
    // define wifi header
    /* const struct wifi_hdr *wifi_header = NULL; */
    // define llc header
    const struct llc_snap_hdr *llc_snap_header = NULL;
    // define ipv4 header
    const struct ipv4_hdr *ipv4_header = NULL;
    // define ipv4 header
    const struct ipv6_hdr *ipv6_header = NULL;
    // define tcp header
    const struct tcp_hdr *tcp_header = NULL;
    // define udp header
    const struct udp_hdr *udp_header = NULL;
    // define payload container
    const u_char *payload = NULL;

    /* lengths and offsets */
    u_int16_t check, type = 0, pyld_eth_len = 0;
    u_int16_t wifi_len = 0, radiotap_len = 0; /* fc; */
    u_int16_t link_offset = 0, ipv4_offset = 0, ipv6_offset = 0;
    u_int16_t tcp_offset = 0, udp_offset = 0;
    u_int16_t size_payload = 0;
    u_int8_t s = fcp->save;

    // check if a SIGINT is arrived
    if(signal_flag){
        /* incoming SIGINT, forcing termination */
        pcap_breakloop(fcp->pcap_handle);
    }

    printf("\n\n==== Got a %d byte packet ====\n", pkt_header->len);

    /* check the datalink type to cast properly datalink header */
    const int datalink_type = pcap_datalink(fcp->pcap_handle);
    switch(datalink_type)
    {
        /** IEEE 802.3 Ethernet - 1 **/
    case DLT_EN10MB:
        ethernet_header = (const struct ether_hdr*)(packet);
        check = ntohs(ethernet_header->type_or_len);
        // ethernet - followed by llc snap 05DC
        if(check <= 1500)
            pyld_eth_len = check;
        // ethernet II - ether type 0600
        else if (check >= 1536)
            type = check;

        // set datalink offset
        link_offset = sizeof(struct ether_hdr);

        // check for LLC layer with SNAP extension
        if(pyld_eth_len != 0) {
            if(packet[link_offset] == SNAP) {
                llc_snap_header = (struct llc_snap_hdr *)(packet + link_offset);
                // SNAP field tells the upper layer protocol
                type = llc_snap_header->type;
                // update datalink offset with LLC/SNAP header len
                link_offset += + 8;
            }
        }
        // update stats
        fcp->stats.ethernet_pkts++;
        break;

        /** Radiotap link-layer**/
    case DLT_IEEE802_11_RADIO:
        radiotap_header = (struct radiotap_hdr *) packet;
        radiotap_len = radiotap_header->len;
        u_int8_t flags;
        // Check for FLAG fields
        flags = getBits(radiotap_header->present, 1, 1);
        printf("Flags = %d\n", flags);

        /* // Check Bad FCS presence */
        /* if((radiotap_header->flags & BAD_FCS) == BAD_FCS) { */
        /* 	fcp->stats.discarded_bytes += pkt_header->len; */
        /* 	return; */
        /* } */
        /* // Calculate 802.11 header length (variable) */
        /* wifi_header = (struct wifi_hdr*)(packet + radiotap_len); */
        /* fc = wifi_header->fc; // FRAME CONTROL BYTES */

        /* // check wifi data presence */
        /* if(FCF_TYPE(fc) == WIFI_DATA) { */
        /* 	if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) || */
        /* 	   (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc))) */
        /* 	  wifi_len = 26; /\* + 4 byte fcs *\/ */
        /* } */
        // no data frames
        /* else */
        
    	break;
        // Wifi data present - check LLC
        llc_snap_header = (struct llc_snap_hdr*)(packet + wifi_len + radiotap_len);
        if(llc_snap_header->dsap == SNAP)
            type = ntohs(llc_snap_header->type);
        else {
            int data = pkt_header->len - radiotap_len - IEEE80211HDR_SIZE;
            printf("Probably a wifi packet of %d bytes with data encription\n", data);
            // update stats
            fcp->stats.wifi_pkts++;
            return;
        }
        link_offset = radiotap_len + wifi_len + sizeof(struct llc_snap_hdr);
        break;

    case DLT_IEEE802:
        link_offset = TOKENRING_SIZE;
        break;

    case DLT_FDDI:
        link_offset = FDDIHDR_SIZE;
        break;

    case DLT_SLIP:
        link_offset = SLIPHDR_SIZE;
        break;

    case DLT_PPP:
        link_offset = PPPHDR_SIZE;
        break;

    case DLT_LOOP:
    case DLT_NULL:
        link_offset = LOOPHDR_SIZE;
        break;

    case DLT_RAW:
        link_offset = RAWHDR_SIZE;
        break;

        /*** Linux Cooked Capture ***/
        #ifdef __linux__
    case DLT_LINUX_SLL:
        type = (packet[link_offset+14] << 8) + packet[link_offset+15];
        link_offset = ISDNHDR_SIZE;
        break;
        #endif

        /*** Wi-fi ***/
        /* case DLT_IEEE802_11: */
        /*   // Calculate 802.11 header length (variable) */
        /*   wifi_header = (struct wifi_hdr*)(packet); */
        /*   fc = wifi_header->fc; */
        /*   // check wifi data presence */
        /*   if(FCF_TYPE(fc) == WIFI_DATA) { */
        /* 	if((FCF_TO_DS(fc) && FCF_FROM_DS(fc) == 0x0) || */
        /* 	   (FCF_TO_DS(fc) == 0x0 && FCF_FROM_DS(fc))) { */
        /* 	  wifi_len = 24; */
        /* 	  link_offset = wifi_len; */
        /* 	} */
        /*   } */
        /*   // no data frames */
        /*   else */
        /* 	link_offset = IEEE80211HDR_SIZE; */
        /*   /\* // Wifi data present - check LLC *\/ */
        /*   /\* link_offset = wifi_len + sizeof(struct llc_hdr); *\/ */
        /* // update stats */
        /* fcp->wifi_pkts++; */
        /*   break; */

    default:
        perror("unsupported interface type\n");
    }

    u_int16_t ipv4_type = 0, ipv6_type = 0;
    /* CHECK ETHER TYPE */
    switch(type)
    {
        // IPv4
    case ETHERTYPE_IPv4:
        ipv4_type = 1;
        break;
        // ARP
    case ETHERTYPE_ARP:
        // update stats
        fcp->stats.arp_pkts++;
        break;
        // IPv6
    case ETHERTYPE_IPv6:
        ipv6_type = 1;
        break;
        // VLAN
    case ETHERTYPE_VLAN:
        // update stats
        fcp->stats.vlan_pkts++;
        vlan_header = (struct vlan_hdr *) (packet + link_offset);
        type = ntohs(vlan_header->type);
        // double tagging for 802.1Q
        if(type == 0x8100) {
            link_offset += 4;
            vlan_header = (struct vlan_hdr *) (packet + link_offset);
            type = ntohs(vlan_header->type);
        }
        ipv4_type = (type == ETHERTYPE_IPv4) ? 1 : 0;
        ipv6_type = (type == ETHERTYPE_IPv6) ? 1 : 0;
        link_offset += 4;
        break;
        // MPLS
    case ETHERTYPE_MPLS_UNI:
    case ETHERTYPE_MPLS_MULTI:
        // update stats
        fcp->stats.mpls_pkts++;
        mpls.u32 = *((uint32_t *) &packet[link_offset]);
        mpls.u32 = ntohl(mpls.u32);
        type = ETHERTYPE_IPv4;
        link_offset += 4;
        // multiple MPLS fields
        while(!mpls.mpls.s) {
            mpls.u32 = *((uint32_t *) &packet[link_offset]);
            mpls.u32 = ntohl(mpls.u32);
            link_offset += 4;
        }
        ipv4_type = 1;
        break;
        // PPPoE
    case ETHERTYPE_PPPoE:
        fcp->stats.pppoe_pkts++;
        break;
    }

    /** Check upper layer protocol **/
    u_int8_t ip_version;
    u_int8_t ip_proto;

    // IPv4
    if(ipv4_type == 1) {
        // decode IP layer
        ip_version = IPv4; // pass to dissector
        ipv4_header = (const struct ipv4_hdr*)(packet + link_offset);
        ipv4_offset = ((u_int16_t)ipv4_header->ihl * 4);
        if(ipv4_offset < 20) {
            fprintf(stderr, "Invalid IPv4 header length: %u bytes\n", ipv4_offset);
            return;
        }
        ip_proto = ipv4_header->ip_proto;
        // update stats
        fcp->stats.ipv4_pkts++;
    }
    // IPv6
    else if(ipv6_type == 1) {
        ip_version = IPv6; // pass to dissector
        ipv6_header = (const struct ipv6_hdr*)(packet + link_offset);
        ipv6_offset = sizeof(const struct ipv6_hdr); //IPV6_HDR_LEN
        if(ipv6_offset < IPV6_HDR_LEN) {
            fprintf(stderr, "Invalid IPv6 header length: %u bytes\n", ipv6_offset);
            return;
        }
        ip_proto = ipv6_header->ipv6_ctlun.ipv6_un1.ipv6_un1_next;
        // update stats
        fcp->stats.ipv6_pkts++;
    }
    // NO IP LAYER
    else {
        fprintf(stderr, "No IP layer found -> skip packet\n");
        fcp->stats.discarded_bytes += pkt_header->len;
        return;
    }

    // set ip_offset
    u_int16_t ip_offset = (ipv4_type == 0) ? ipv6_offset : ipv4_offset;

    // decode transport layer
    switch(ip_proto)
    {
    case IPPROTO_TCP: // TCP
        printf("\t Protocol: TCP\n");
        tcp_header = (const struct tcp_hdr *)(packet + link_offset + ip_offset);
        tcp_offset = tcp_header->tcp_offset * 4;
        if(tcp_offset < 20) {
            fprintf(stderr, "Invalid TCP header length: %u bytes\n", tcp_offset);
            return;
        }
        // update stats
        fcp->stats.tcp_pkts++;
        break;
    case IPPROTO_UDP: // UDP
        printf("\t Protocol: UDP\n");
        udp_header = (const struct udp_hdr *)(packet + link_offset + ip_offset);
        // calculate udp header length is useless (UDP header is always 8 byte)
        udp_offset = UDP_HDR_LEN;
        // update stats
        fcp->stats.udp_pkts++;
        break;
    default:
        printf("\t Protocol: unknown\n");
        return;
    }

    // set l4 offset
    u_int16_t l4_offset = (ip_proto == IPPROTO_TCP) ? tcp_offset : udp_offset;

    // decode payload
    payload = ((u_char *)(packet + link_offset + ip_offset + l4_offset));

    // compute tcp payload (segment) size
    size_payload = pkt_header->len - ip_offset - l4_offset - link_offset;
    // TODO check if we have VSS-monitoring ethernet trailer in latest 2 bytes
    size_payload = check_vss_trailer(payload, size_payload);
    
    if(size_payload > 0)
        printf("\t Payload (%d bytes):\n", size_payload);

    /**
       This is the function to process a packet.

       The args are usefull to create the key for the Hashtable
       Inside the function there is the handle of Hashtable and Flow
    **/
    check = process_packet(payload,
                           size_payload,
                           ip_version,
                           ipv4_header,
                           ipv6_header,
                           (ip_proto == IPPROTO_TCP) ? ntohs(tcp_header->tcp_src_port) : ntohs(udp_header->udp_src_port),
                           (ip_proto == IPPROTO_TCP) ? ntohs(tcp_header->tcp_dst_port) : ntohs(udp_header->udp_dst_port),
                           ip_proto,
                           fcp,
                           s
                           /* HT_Flows */);
    if(check == 4) { //TODO FIX
        printf("TLS/SSL packet found and parsed\n");
        fcp->stats.num_tls_pkts++;
        print_HashTable(ip_version);
    }
    else if(check == 3) {
        printf("DIAMETER Protocol found and parsed\n");
        fcp->stats.num_diameter_pkts++;
    }
    else if(check == 2) {
        printf("NGCP Protocol found and parsed\n");
        fcp->stats.num_ngcp_pkts++;
    }
    else if(check == 1) {
        printf("RTCP Protocol found and parsed\n");
        fcp->stats.num_rtcp_pkts++;
    }
    else if(check == 5) {
        printf("RTSP Protocol found and parsed\n");
        fcp->stats.num_rtsp_pkts++;
    }
    else if(check == 0) {
        printf("MSRP Protocol found and parsed\n");
        fcp->stats.num_msrp_pkts++;
    }
    else {
        printf("\n\t Other protocols\n\n");
    }
}

/**
   Print statistic about the entire session
*/
void print_stats(struct flow_callback_proto * fcp)
{
    printf(" \n---------- DECODER STATISTICS ----------\n\n");

    printf(" # Discarded bytes             = %d\n",   fcp->stats.discarded_bytes);
    printf(" # Ethernet pkts               = %d\n",   fcp->stats.ethernet_pkts);

    printf(" # ARP pkts                    = %d\n",   fcp->stats.arp_pkts);
    printf(" # IPv4 pkts                   = %d\n",   fcp->stats.ipv4_pkts);
    printf(" # IPv6 pkts                   = %d\n",   fcp->stats.ipv6_pkts);

    printf(" # VLAN pkts                   = %d\n",   fcp->stats.vlan_pkts);
    printf(" # MPLS pkts                   = %d\n",   fcp->stats.mpls_pkts);
    printf(" # PPPoE pkts                  = %d\n",   fcp->stats.pppoe_pkts);

    printf(" # TCP pkts                    = %d\n",   fcp->stats.tcp_pkts);
    printf(" # UDP pkts                    = %d\n\n", fcp->stats.udp_pkts);

    printf("\033[0;33m");
    printf(" # TLS handshake pkts          = %d\n",   fcp->stats.num_tls_pkts);
    printf(" # RTCP pkts                   = %d\n",   fcp->stats.num_rtcp_pkts);
    printf(" # DIAMETER pkts               = %d\n",   fcp->stats.num_diameter_pkts);
    printf(" # NGCP pkts                   = %d\n",   fcp->stats.num_ngcp_pkts);
    printf(" # RTSP pkts                   = %d\n",   fcp->stats.num_rtsp_pkts);
    printf(" # MSRP pkts                   = %d\n",   fcp->stats.num_msrp_pkts);
    printf("\033[0m");

    printf(" ---------- ------------------ ----------\n\n");
}

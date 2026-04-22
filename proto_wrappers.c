#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "functions.h"
#include "dissector.h"
#include "proto_wrappers.h"

#define JSON_BUFFER_LEN 5000

static int dissect_gtp(const dissector_ctx_t *ctx)
{
    int ret;
    char *json_buffer = calloc(JSON_BUFFER_LEN, sizeof(char));
    if (!json_buffer)
        return DISSECT_ERR;

    ret = gtp_parser(ctx->payload,
                     ctx->size_payload,
                     ctx->src_port,
                     ctx->dst_port,
                     json_buffer,
                     JSON_BUFFER_LEN);
    free(json_buffer);

    if (ret > 0)
        return DISSECT_OK;
    if (ret < 0)
        return DISSECT_ERR;
    return DISSECT_SKIP;
}

static int dissect_ngcp(const dissector_ctx_t *ctx)
{
    struct msg_fake_sip *msg_sf = ngcp_parser(ctx->payload, ctx->size_payload);
    if (!msg_sf)
        return DISSECT_SKIP;

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
    printf("a-number: %s\n", msg_sf->a_number);
    printf("\033[0m");
    printf("\033[1;31m");
    printf("b-number: %s\n", msg_sf->b_number);
    printf("\033[0m");
    printf("\033[1;31m");
    printf("\n-------------------- --- ---- --- -------------------- \n");
    printf("\n-------------------- --- ---- --- -------------------- \n");
    printf("\033[0m");

    return DISSECT_OK;
}

static int dissect_rtp(const dissector_ctx_t *ctx)
{
    int ret = check_rtp_version(ctx->payload, ctx->size_payload);
    if (ret == -1)
        return DISSECT_ERR;
    if (ret == -2)
        return DISSECT_SKIP;

    char *json_buffer = calloc(JSON_BUFFER_LEN, sizeof(char));
    if (!json_buffer)
        return DISSECT_ERR;

    ret = rtp_parser(ctx->payload,
                     ctx->size_payload,
                     json_buffer,
                     JSON_BUFFER_LEN);
    if (ret > 0)
        printf("%s\n\n", json_buffer);
    free(json_buffer);

    if (ret == -1)
        return DISSECT_SKIP;
    return DISSECT_OK;
}

static int dissect_rtcp(const dissector_ctx_t *ctx)
{
    int ret = check_rtcp_version(ctx->payload, ctx->size_payload);
    if (ret == -1)
        return DISSECT_ERR;
    if (ret == -2 || ret == -3)
        return DISSECT_SKIP;

    char *json_buffer = calloc(JSON_BUFFER_LEN, sizeof(char));
    if (!json_buffer)
        return DISSECT_ERR;

    ret = rtcp_parser(ctx->payload,
                      ctx->size_payload,
                      json_buffer,
                      JSON_BUFFER_LEN);
    if (ret > 0)
        printf("%s\n\n", json_buffer);
    free(json_buffer);

    if (ret == -1)
        return DISSECT_SKIP;
    return DISSECT_OK;
}

static int dissect_rtsp(const dissector_ctx_t *ctx)
{
    int ret;
    char *json_buffer = calloc(JSON_BUFFER_LEN, sizeof(char));
    if (!json_buffer)
        return DISSECT_ERR;

    ret = rtsp_parser(ctx->payload,
                      ctx->size_payload,
                      json_buffer,
                      JSON_BUFFER_LEN);
    if (ret >= 0)
        printf("%s\n", json_buffer);
    free(json_buffer);

    if (ret < 0)
        return DISSECT_SKIP;
    return DISSECT_OK;
}

static int dissect_tls(const dissector_ctx_t *ctx)
{
    int ret;
    const u_char *payload = ctx->payload;
    struct Flow_key  *flow_key  = NULL;
    struct Handshake *handshake = NULL;
    char *json_buffer = calloc(JSON_BUFFER_LEN, sizeof(char));

    if (!json_buffer)
        return DISSECT_ERR;
    memset(json_buffer, 0, JSON_BUFFER_LEN);

    if (!ctx->payload || ctx->size_payload <= 0 ||
        (ctx->ip_version != 4 && ctx->ip_version != 6) || (!ctx->iphv4 && !ctx->iphv6) ||
        ctx->proto_id_l3 <= 0 || !ctx->fcp) {
        fprintf(stderr, "\t Discard packet\n");
        free(json_buffer);
        return DISSECT_ERR;
    }

    flow_key = malloc(sizeof(struct Flow_key));
    if (!flow_key) {
        free(json_buffer);
        return DISSECT_ERR;
    }
    memset(flow_key, 0, sizeof(struct Flow_key));

    if (ctx->ip_version == IPv4) {
        flow_key->ip_src = ctx->iphv4->ip_src_addr;
        flow_key->ip_dst = ctx->iphv4->ip_dst_addr;
    }
    else {
        flow_key->ipv6_src.ipv6_addr[0] = ctx->iphv6->ipv6_src.ipv6_addr[0];
        flow_key->ipv6_src.ipv6_addr[1] = ctx->iphv6->ipv6_src.ipv6_addr[1];
        flow_key->ipv6_src.ipv6_addr[2] = ctx->iphv6->ipv6_src.ipv6_addr[2];
        flow_key->ipv6_src.ipv6_addr[3] = ctx->iphv6->ipv6_src.ipv6_addr[3];
        flow_key->ipv6_src.ipv6_addr[4] = ctx->iphv6->ipv6_src.ipv6_addr[4];
        flow_key->ipv6_src.ipv6_addr[5] = ctx->iphv6->ipv6_src.ipv6_addr[5];
        flow_key->ipv6_src.ipv6_addr[6] = ctx->iphv6->ipv6_src.ipv6_addr[6];
        flow_key->ipv6_src.ipv6_addr[7] = ctx->iphv6->ipv6_src.ipv6_addr[7];
        flow_key->ipv6_src.ipv6_addr[8] = ctx->iphv6->ipv6_src.ipv6_addr[8];
        flow_key->ipv6_src.ipv6_addr[9] = ctx->iphv6->ipv6_src.ipv6_addr[9];
        flow_key->ipv6_src.ipv6_addr[10] = ctx->iphv6->ipv6_src.ipv6_addr[10];
        flow_key->ipv6_src.ipv6_addr[11] = ctx->iphv6->ipv6_src.ipv6_addr[11];
        flow_key->ipv6_src.ipv6_addr[12] = ctx->iphv6->ipv6_src.ipv6_addr[12];
        flow_key->ipv6_src.ipv6_addr[13] = ctx->iphv6->ipv6_src.ipv6_addr[13];
        flow_key->ipv6_src.ipv6_addr[14] = ctx->iphv6->ipv6_src.ipv6_addr[14];
        flow_key->ipv6_src.ipv6_addr[15] = ctx->iphv6->ipv6_src.ipv6_addr[15];
        flow_key->ipv6_dst.ipv6_addr[0] = ctx->iphv6->ipv6_dst.ipv6_addr[0];
        flow_key->ipv6_dst.ipv6_addr[1] = ctx->iphv6->ipv6_dst.ipv6_addr[1];
        flow_key->ipv6_dst.ipv6_addr[2] = ctx->iphv6->ipv6_dst.ipv6_addr[2];
        flow_key->ipv6_dst.ipv6_addr[3] = ctx->iphv6->ipv6_dst.ipv6_addr[3];
        flow_key->ipv6_dst.ipv6_addr[4] = ctx->iphv6->ipv6_dst.ipv6_addr[4];
        flow_key->ipv6_dst.ipv6_addr[5] = ctx->iphv6->ipv6_dst.ipv6_addr[5];
        flow_key->ipv6_dst.ipv6_addr[6] = ctx->iphv6->ipv6_dst.ipv6_addr[6];
        flow_key->ipv6_dst.ipv6_addr[7] = ctx->iphv6->ipv6_dst.ipv6_addr[7];
        flow_key->ipv6_dst.ipv6_addr[8] = ctx->iphv6->ipv6_dst.ipv6_addr[8];
        flow_key->ipv6_dst.ipv6_addr[9] = ctx->iphv6->ipv6_dst.ipv6_addr[9];
        flow_key->ipv6_dst.ipv6_addr[10] = ctx->iphv6->ipv6_dst.ipv6_addr[10];
        flow_key->ipv6_dst.ipv6_addr[11] = ctx->iphv6->ipv6_dst.ipv6_addr[11];
        flow_key->ipv6_dst.ipv6_addr[12] = ctx->iphv6->ipv6_dst.ipv6_addr[12];
        flow_key->ipv6_dst.ipv6_addr[13] = ctx->iphv6->ipv6_dst.ipv6_addr[13];
        flow_key->ipv6_dst.ipv6_addr[14] = ctx->iphv6->ipv6_dst.ipv6_addr[14];
        flow_key->ipv6_dst.ipv6_addr[15] = ctx->iphv6->ipv6_dst.ipv6_addr[15];
    }

    flow_key->src_port = ctx->src_port;
    flow_key->dst_port = ctx->dst_port;
    flow_key->proto_id_l3 = ctx->proto_id_l3;

    ret = tls_parser(&payload,
                     ctx->size_payload,
                     ctx->ip_version,
                     flow_key,
                     ctx->src_port,
                     ctx->dst_port,
                     ctx->proto_id_l3,
                     ctx->save);

    free(json_buffer);

    if (ret == -1) {
        free(flow_key);
        free(handshake);
        return DISSECT_SKIP;
    }

    return DISSECT_OK;
}

static int dissect_diameter(const dissector_ctx_t *ctx)
{
    int ret;
    char *json_buffer = calloc(JSON_BUFFER_LEN, sizeof(char));
    if (!json_buffer)
        return DISSECT_ERR;

    ret = diameter_parser(ctx->payload,
                          ctx->size_payload,
                          json_buffer,
                          JSON_BUFFER_LEN);
    if (ret != -1)
        printf("%s\n", json_buffer);
    free(json_buffer);

    if (ret == -1)
        return DISSECT_SKIP;
    return DISSECT_OK;
}

void register_all_dissectors(void)
{
    static int initialized = 0;

    if (initialized)
        return;

    dissector_register(IPPROTO_TCP, 443,  dissect_tls,      "TLS",      4);
    dissector_register(IPPROTO_TCP, 3868, dissect_diameter, "DIAMETER", 3);
    dissector_register(IPPROTO_UDP, 2152, dissect_gtp,      "GTP",      7);
    dissector_register(IPPROTO_UDP, 2123, dissect_gtp,      "GTP",      7);
    dissector_register(IPPROTO_UDP, 3386, dissect_gtp,      "GTP",      7);
    dissector_register(IPPROTO_TCP, 554,  dissect_rtsp,     "RTSP",     5);
    dissector_register(IPPROTO_TCP, 2152, dissect_gtp,      "GTP",      7);
    dissector_register(IPPROTO_UDP, 0,    dissect_ngcp,     "NGCP",     2);
    dissector_register(IPPROTO_UDP, 0,    dissect_rtp,      "RTP",      6);
    dissector_register(IPPROTO_UDP, 0,    dissect_rtcp,     "RTCP",     1);

    initialized = 1;
}

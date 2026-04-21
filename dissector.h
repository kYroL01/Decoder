#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stdint.h>
#include "structures.h"

#define DISSECT_OK     1
#define DISSECT_SKIP   0
#define DISSECT_ERR   -1

typedef struct dissector_ctx {
    const u_char              *payload;
    uint16_t                   size_payload;
    uint8_t                    ip_version;
    const struct ipv4_hdr     *iphv4;
    const struct ipv6_hdr     *iphv6;
    uint16_t                   src_port;
    uint16_t                   dst_port;
    uint8_t                    proto_id_l3;
    struct flow_callback_proto *fcp;
    uint8_t                    save;
} dissector_ctx_t;

typedef int (*dissect_fn)(const dissector_ctx_t *ctx);

typedef struct dissector_entry {
    uint8_t    l4_proto;   /* IPPROTO_TCP, IPPROTO_UDP, or 0 = wildcard */
    uint16_t   port;       /* 0 = heuristic-only, no port filter */
    dissect_fn fn;
    const char *name;
    int         ret_code;  /* the integer returned to callback_proto on match */
} dissector_entry_t;

void dissector_register(uint8_t l4_proto, uint16_t port,
                        dissect_fn fn, const char *name, int ret_code);
int  dissector_run(const dissector_ctx_t *ctx);
void register_all_dissectors(void);

#endif /* DISSECTOR_H */

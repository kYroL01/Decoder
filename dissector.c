#include <stdio.h>
#include "dissector.h"

#define MAX_DISSECTORS 32

static dissector_entry_t registry[MAX_DISSECTORS];
static int registry_count = 0;

void dissector_register(uint8_t l4_proto, uint16_t port,
                        dissect_fn fn, const char *name, int ret_code)
{
    if (registry_count >= MAX_DISSECTORS) {
        fprintf(stderr, "dissector registry full, cannot register %s\n", name);
        return;
    }
    registry[registry_count++] = (dissector_entry_t){
        .l4_proto = l4_proto,
        .port     = port,
        .fn       = fn,
        .name     = name,
        .ret_code = ret_code,
    };
}

int dissector_run(const dissector_ctx_t *ctx)
{
    int i;

    for (i = 0; i < registry_count; i++) {
        int ret;
        const dissector_entry_t *e = &registry[i];

        if (e->l4_proto != 0 && e->l4_proto != ctx->proto_id_l3)
            continue;
        if (e->port != 0 &&
            e->port != ctx->src_port &&
            e->port != ctx->dst_port)
            continue;

        ret = e->fn(ctx);
        if (ret == DISSECT_OK) {
            printf("%s protocol FOUND and parsed\n", e->name);
            return e->ret_code;
        }
        if (ret == DISSECT_ERR)
            fprintf(stderr, "%s dissector error\n", e->name);
        /* DISSECT_SKIP -> continue to next */
    }
    return 0; /* no dissector matched */
}

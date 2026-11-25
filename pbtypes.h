/* pbtypes.h - shared decoders for common Omniston types (ChainAddress, AssetId). Header-only. */
#ifndef PBTYPES_H
#define PBTYPES_H
#include <stdio.h>
#include "pb.h"

static inline const char *chain_name(uint32_t f) {
    static const char *n[] = {"", "arbitrum", "avalanche", "base", "bnb", "ethereum", "polygon",
                              "robinhood", "xlayer", "arc", "monad", "plasma", "hyperevm", "elysium"};
    if (f >= 1 && f <= 13) return n[f];
    if (f == 50) return "ton";
    if (f == 60) return "tron";
    return "unknown";
}

/* ChainAddress -> "ton:EQ..." ; *chain = oneof field number */
static inline int parse_caddr(const uint8_t *d, size_t n, char *out, size_t cap, uint32_t *chain) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l;
    if (pbr_next(&r, &f, &w, &v, &p, &l) != 1 || w != 2) return -1;
    if (chain) *chain = f;
    snprintf(out, cap, "%s:%.*s", chain_name(f), (int)l, (const char *)p);
    return 0;
}

/* AssetId -> "ton:native" | "ton:<jetton>" | "bnb:0x..." ; *chain = oneof field number */
static inline int parse_asset(const uint8_t *d, size_t n, char *out, size_t cap, uint32_t *chain) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l;
    if (pbr_next(&r, &f, &w, &v, &p, &l) != 1 || w != 2) return -1;
    if (chain) *chain = f;
    pbr_t k; pbr_init(&k, p, l);
    const char *name = chain_name(f);
    if (pbr_next(&k, &f, &w, &v, &p, &l) != 1 || w != 2) return -1;
    if (f == 1) { snprintf(out, cap, "%s:native", name); return 0; }
    if (f == 2) { snprintf(out, cap, "%s:%.*s", name, (int)l, (const char *)p); return 0; }
    if (f == 3) {
        pbr_t m; pbr_init(&m, p, l);
        char c[64] = "", t[48] = "";
        while (pbr_next(&m, &f, &w, &v, &p, &l) == 1) {
            if (w == 2 && f == 1) snprintf(c, sizeof c, "%.*s", (int)l, (const char *)p);
            else if (w == 2 && f == 2) snprintf(t, sizeof t, "%.*s", (int)l, (const char *)p);
        }
        snprintf(out, cap, "%s:%s#%s", name, c, t); return 0;
    }
    return -1;
}

static inline void pb_cpy(char *dst, size_t cap, const uint8_t *p, size_t l) {
    snprintf(dst, cap, "%.*s", (int)l, (const char *)p);
}
#endif

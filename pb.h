/* pb.h - minimal protobuf wire-format writer/reader (no allocation).
 * Only what the Omniston resolver client needs: varint, length-delimited. */
#ifndef PB_H
#define PB_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---------------- writer ---------------- */
typedef struct { uint8_t *p; size_t cap, len; int err; } pbw_t;

static inline void pbw_init(pbw_t *w, uint8_t *buf, size_t cap) {
    w->p = buf; w->cap = cap; w->len = 0; w->err = 0;
}
static inline void pbw_raw(pbw_t *w, const void *d, size_t n) {
    if (w->err || w->len + n > w->cap) { w->err = 1; return; }
    memcpy(w->p + w->len, d, n);
    w->len += n;
}
static inline void pbw_varint(pbw_t *w, uint64_t v) {
    uint8_t b[10]; int n = 0;
    do { uint8_t c = v & 0x7f; v >>= 7; if (v) c |= 0x80; b[n++] = c; } while (v);
    pbw_raw(w, b, (size_t)n);
}
static inline void pbw_tag(pbw_t *w, uint32_t field, uint32_t wire) {
    pbw_varint(w, ((uint64_t)field << 3) | wire);
}
static inline void pbw_u64(pbw_t *w, uint32_t field, uint64_t v) {
    pbw_tag(w, field, 0); pbw_varint(w, v);
}
static inline void pbw_bytes(pbw_t *w, uint32_t field, const void *d, size_t n) {
    pbw_tag(w, field, 2); pbw_varint(w, n); pbw_raw(w, d, n);
}
static inline void pbw_str(pbw_t *w, uint32_t field, const char *s) {
    pbw_bytes(w, field, s, strlen(s));
}

/* ---------------- reader ---------------- */
typedef struct { const uint8_t *p, *end; } pbr_t;

static inline void pbr_init(pbr_t *r, const uint8_t *d, size_t n) { r->p = d; r->end = d + n; }

static inline int pbr_varint(pbr_t *r, uint64_t *out) {
    uint64_t v = 0; int shift = 0;
    while (r->p < r->end && shift < 64) {
        uint8_t c = *r->p++;
        v |= (uint64_t)(c & 0x7f) << shift;
        if (!(c & 0x80)) { *out = v; return 1; }
        shift += 7;
    }
    return 0;
}

/* Returns 1 = field read, 0 = clean end, -1 = malformed.
 * wire 0 -> *val; wire 2 -> (*data,*len); wire 1/5 -> *val (raw bits). */
static inline int pbr_next(pbr_t *r, uint32_t *field, uint32_t *wire, uint64_t *val,
                           const uint8_t **data, size_t *len) {
    uint64_t tag;
    if (r->p >= r->end) return 0;
    if (!pbr_varint(r, &tag)) return -1;
    *field = (uint32_t)(tag >> 3);
    *wire = (uint32_t)(tag & 7);
    switch (*wire) {
    case 0: return pbr_varint(r, val) ? 1 : -1;
    case 1:
        if (r->end - r->p < 8) return -1;
        memcpy(val, r->p, 8); r->p += 8; return 1;
    case 2: {
        uint64_t n;
        if (!pbr_varint(r, &n) || n > (uint64_t)(r->end - r->p)) return -1;
        *data = r->p; *len = (size_t)n; r->p += n; return 1;
    }
    case 5: {
        uint32_t v;
        if (r->end - r->p < 4) return -1;
        memcpy(&v, r->p, 4); *val = v; r->p += 4; return 1;
    }
    default: return -1;
    }
}

static inline int64_t pb_zigzag(uint64_t v) { return (int64_t)(v >> 1) ^ -(int64_t)(v & 1); }

#endif

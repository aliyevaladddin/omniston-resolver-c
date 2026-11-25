/* escrow.c - parsers for OrderUpdated/OrderClosed/ExecutionUpdated/ResolverAddressSigned + sign cache.
 * No network, no allocation. See escrow.h. */
#include "escrow.h"
#include <stdio.h>
#include <string.h>
#include "pbtypes.h"

#define MAX_ORDERS 64
#define MAX_SIGS   8

static escrow_log_fn g_log;
static escrow_hooks_t g_hooks;
static escrow_order_t g_orders[MAX_ORDERS];
static int g_order_used[MAX_ORDERS];
static escrow_signed_t g_sigs[MAX_SIGS];
static int g_sig_used[MAX_SIGS];
static char g_last_ton_contract[ESC_ADDR];

#define LG(...) do { if (g_log) g_log(__VA_ARGS__); } while (0)

const char *escrow_phase_name(int p) {
    switch (p) {
    case 0: return "CREATED";
    case 1: return "READY_FOR_PRIVATE_COMPLETION";
    case 2: return "READY_FOR_PUBLIC_COMPLETION";
    case 3: return "READY_FOR_PRIVATE_ROLLBACK";
    case 4: return "READY_FOR_PUBLIC_ROLLBACK";
    case 10: return "COMPLETED";
    case 11: return "ROLLED_BACK";
    case -1: return "-";
    default: return "?";
    }
}

/* ------------------------------------------------------------ sub-parsers */
static void parse_order_settlement(const uint8_t *d, size_t n, escrow_quote_t *q) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l;
    q->has_order_settlement = 1;
    while (pbr_next(&r, &f, &w, &v, &p, &l) == 1) {
        if (w == 2) switch (f) {
        case 1:  parse_caddr(p, l, q->src_protocol_contract, sizeof q->src_protocol_contract, NULL); break;
        case 2:  parse_caddr(p, l, q->src_wrapped_native, sizeof q->src_wrapped_native, NULL); break;
        case 3:  parse_caddr(p, l, q->src_initial_resolver, sizeof q->src_initial_resolver, NULL); break;
        case 10: parse_caddr(p, l, q->dst_protocol_contract, sizeof q->dst_protocol_contract, NULL); break;
        case 11: pb_cpy(q->resolver_sends_units, sizeof q->resolver_sends_units, p, l); break;
        case 12: parse_caddr(p, l, q->dst_wrapped_native, sizeof q->dst_wrapped_native, NULL); break;
        default: break;
        } else if (w == 0) switch (f) {
        case 20: q->trade_start_deadline = v; break;
        case 21: q->exclusivity_timeout = v; break;
        case 30: q->integrator_fee_pips = (uint32_t)v; break;
        case 31: q->protocol_fee_pips = (uint32_t)v; break;
        default: break;
        }
    }
}

static int parse_quote(const uint8_t *d, size_t n, escrow_quote_t *q) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l; int rc;
    while ((rc = pbr_next(&r, &f, &w, &v, &p, &l)) == 1) {
        if (w == 2) switch (f) {
        case 1:  pb_cpy(q->rfq_id, sizeof q->rfq_id, p, l); break;
        case 2:  pb_cpy(q->quote_id, sizeof q->quote_id, p, l); break;
        case 3:  pb_cpy(q->resolver_id, sizeof q->resolver_id, p, l); break;
        case 4:  pb_cpy(q->resolver_name, sizeof q->resolver_name, p, l); break;
        case 10: parse_asset(p, l, q->in_asset, sizeof q->in_asset, NULL); break;
        case 11: parse_asset(p, l, q->out_asset, sizeof q->out_asset, NULL); break;
        case 12: pb_cpy(q->input_units, sizeof q->input_units, p, l); break;
        case 13: pb_cpy(q->output_units, sizeof q->output_units, p, l); break;
        case 21: pb_cpy(q->integrator_fee_units, sizeof q->integrator_fee_units, p, l); break;
        case 22: pb_cpy(q->protocol_fee_units, sizeof q->protocol_fee_units, p, l); break;
        case 41: parse_order_settlement(p, l, q); break;
        default: break;
        } else if (w == 0 && f == 30) q->quote_timestamp = v;
    }
    return rc < 0 ? -1 : 0;
}

static void parse_blob(const uint8_t *p, size_t l, uint8_t *dst, size_t cap, size_t *len, int *trunc) {
    *trunc = l > cap;
    *len = l > cap ? cap : l;
    memcpy(dst, p, *len);
}

/* handles fields shared by OrderUpdated/ExecutionUpdated: 20 order_details, 21 escrow, 22 signed, 30 dst params */
static void parse_position_field(uint32_t f, const uint8_t *p, size_t l, escrow_position_t *pos) {
    switch (f) {
    case 20: parse_blob(p, l, pos->order_details, sizeof pos->order_details, &pos->order_details_len, &pos->order_details_truncated); break;
    case 21: parse_caddr(p, l, pos->escrow_address, sizeof pos->escrow_address, NULL); break;
    case 22: pos->has_signed_order = 1; pos->signed_order_len = l; break;
    case 30: {                                   /* HtlcDstPositionParams{ ton=1{ condition_code_cell=1 } } */
        pbr_t a; pbr_init(&a, p, l);
        uint32_t f1, w1; uint64_t v1; const uint8_t *p1; size_t l1;
        while (pbr_next(&a, &f1, &w1, &v1, &p1, &l1) == 1) if (f1 == 1 && w1 == 2) {
            pbr_t b; pbr_init(&b, p1, l1);
            uint32_t f2, w2; uint64_t v2; const uint8_t *p2; size_t l2;
            while (pbr_next(&b, &f2, &w2, &v2, &p2, &l2) == 1) if (f2 == 1 && w2 == 2)
                parse_blob(p2, l2, pos->dst_condition_code, sizeof pos->dst_condition_code,
                           &pos->dst_condition_code_len, &pos->dst_code_truncated);
        }
        break;
    }
    default: break;
    }
}

static void parse_phase_ts(const uint8_t *d, size_t n, uint64_t *pc, uint64_t *pub_c, uint64_t *pr, uint64_t *pub_r) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l;
    while (pbr_next(&r, &f, &w, &v, &p, &l) == 1) if (w == 0) switch (f) {
        case 1: *pc = v; break; case 2: *pub_c = v; break; case 3: *pr = v; break; case 4: *pub_r = v; break;
        default: break;
    }
}

static int parse_execution(const uint8_t *d, size_t n, escrow_execution_t *e) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l; int rc;
    e->input_phase = e->output_phase = -1;
    while ((rc = pbr_next(&r, &f, &w, &v, &p, &l)) == 1) {
        if (w == 2) switch (f) {
        case 2: pb_cpy(e->input_units, sizeof e->input_units, p, l); break;
        case 3: pb_cpy(e->output_units, sizeof e->output_units, p, l); break;
        case 4: pb_cpy(e->resolver_sends_units, sizeof e->resolver_sends_units, p, l); break;
        case 5: e->secret_hash_len = l > sizeof e->secret_hash ? sizeof e->secret_hash : l;
                memcpy(e->secret_hash, p, e->secret_hash_len); break;
        case 6: pb_cpy(e->resolver_id, sizeof e->resolver_id, p, l); break;
        case 7: pb_cpy(e->resolver_name, sizeof e->resolver_name, p, l); break;
        case 10: parse_caddr(p, l, e->input_position_address, sizeof e->input_position_address, NULL); break;
        case 12: parse_phase_ts(p, l, &e->in_private_completion, &e->in_public_completion,
                                &e->in_private_rollback, &e->in_public_rollback); break;
        case 13: parse_caddr(p, l, e->src_resolver_address, sizeof e->src_resolver_address, NULL); break;
        case 20: parse_caddr(p, l, e->output_position_address, sizeof e->output_position_address, NULL); break;
        case 22: parse_phase_ts(p, l, &e->out_private_completion, &e->out_public_completion,
                                &e->out_private_rollback, &e->out_public_rollback); break;
        default: break;
        } else if (w == 0) switch (f) {
        case 1: e->index = v; break;
        case 11: e->input_phase = (int)v; break;
        case 21: e->output_phase = (int)v; break;
        default: break;
        }
    }
    return rc < 0 ? -1 : 0;
}

/* ---------------------------------------------------------------- events */
static int on_order_updated(const uint8_t *d, size_t n) {
    static escrow_order_t o;                /* static: struct is ~6 KB, keep it off the stack */
    memset(&o, 0, sizeof o);
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l; int rc;
    while ((rc = pbr_next(&r, &f, &w, &v, &p, &l)) == 1) {
        if (w == 2) switch (f) {
        case 1:  parse_quote(p, l, &o.q); break;
        case 2:  pb_cpy(o.remaining_input_units, sizeof o.remaining_input_units, p, l); break;
        case 11: parse_caddr(p, l, o.exclusive_resolver, sizeof o.exclusive_resolver, NULL); break;
        case 20: case 21: case 22: case 30: parse_position_field(f, p, l, &o.pos); break;
        default: break;
        } else if (w == 0) switch (f) {
        case 3:  o.remaining_secrets = v; break;
        case 10: o.cancellation_available_timestamp = v; break;
        default: break;
        }
    }
    if (rc < 0 || !o.q.quote_id[0]) { LG("[escrow] malformed OrderUpdatedEvent"); return 1; }

    int slot = -1, is_new = 1;
    for (int i = 0; i < MAX_ORDERS; i++) {
        if (g_order_used[i] && !strcmp(g_orders[i].q.quote_id, o.q.quote_id)) { slot = i; is_new = 0; break; }
        if (!g_order_used[i] && slot < 0) slot = i;
    }
    if (slot < 0) { LG("[escrow] order table full, not storing %s", o.q.quote_id); }
    else { g_orders[slot] = o; g_order_used[slot] = 1; }

    LG("[escrow] ORDER %s quote=%s %s -> %s in=%s out=%s remaining=%s secrets=%llu cancel_ts=%llu",
       is_new ? "NEW" : "UPDATE", o.q.quote_id, o.q.in_asset, o.q.out_asset, o.q.input_units, o.q.output_units,
       o.remaining_input_units, (unsigned long long)o.remaining_secrets,
       (unsigned long long)o.cancellation_available_timestamp);
    LG("[escrow]   escrow=%s signed_order=%d protocol=%s exclusive=%s sends=%s deadline=%llu excl_timeout=%llu details=%zuB code=%zuB",
       o.pos.escrow_address[0] ? o.pos.escrow_address : "-", o.pos.has_signed_order,
       o.q.src_protocol_contract[0] ? o.q.src_protocol_contract : "-",
       o.exclusive_resolver[0] ? o.exclusive_resolver : "-", o.q.resolver_sends_units,
       (unsigned long long)o.q.trade_start_deadline, (unsigned long long)o.q.exclusivity_timeout,
       o.pos.order_details_len, o.pos.dst_condition_code_len);
    if (!strncmp(o.q.src_protocol_contract, "ton:", 4) && o.q.src_protocol_contract[4]) {
        memcpy(g_last_ton_contract, o.q.src_protocol_contract + 4, ESC_ADDR - 4);
        g_last_ton_contract[ESC_ADDR - 4] = '\0';
    }
    if (g_hooks.on_order) g_hooks.on_order(&o, is_new);
    return 1;
}

static int on_order_closed(const uint8_t *d, size_t n) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l;
    char qid[ESC_ID] = "";
    while (pbr_next(&r, &f, &w, &v, &p, &l) == 1) if (f == 1 && w == 2) pb_cpy(qid, sizeof qid, p, l);
    for (int i = 0; i < MAX_ORDERS; i++)
        if (g_order_used[i] && !strcmp(g_orders[i].q.quote_id, qid)) g_order_used[i] = 0;
    LG("[escrow] ORDER CLOSED quote=%s", qid);
    if (g_hooks.on_closed) g_hooks.on_closed(qid);
    return 1;
}

static int on_execution_updated(const uint8_t *d, size_t n) {
    static escrow_exec_event_t e;
    memset(&e, 0, sizeof e);
    e.ex.input_phase = e.ex.output_phase = -1;
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l; int rc;
    while ((rc = pbr_next(&r, &f, &w, &v, &p, &l)) == 1) {
        if (w != 2) continue;
        switch (f) {
        case 1:  parse_quote(p, l, &e.q); break;
        case 2:  parse_execution(p, l, &e.ex); break;
        case 10: e.secret_len = l > sizeof e.secret ? sizeof e.secret : l; memcpy(e.secret, p, e.secret_len); break;
        case 20: case 21: case 22: case 30: parse_position_field(f, p, l, &e.pos); break;
        default: break;
        }
    }
    if (rc < 0) { LG("[escrow] malformed ExecutionUpdatedEvent"); return 1; }
    LG("[escrow] EXECUTION quote=%s idx=%llu in=%s out=%s sends=%s in_phase=%s out_phase=%s in_pos=%s out_pos=%s secret=%s",
       e.q.quote_id, (unsigned long long)e.ex.index, e.ex.input_units, e.ex.output_units, e.ex.resolver_sends_units,
       escrow_phase_name(e.ex.input_phase), escrow_phase_name(e.ex.output_phase),
       e.ex.input_position_address[0] ? e.ex.input_position_address : "-",
       e.ex.output_position_address[0] ? e.ex.output_position_address : "-", e.secret_len ? "revealed" : "-");
    if (g_hooks.on_execution) g_hooks.on_execution(&e);
    return 1;
}

static int on_address_signed(const uint8_t *d, size_t n) {
    escrow_signed_t s; memset(&s, 0, sizeof s);
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l; int rc;
    while ((rc = pbr_next(&r, &f, &w, &v, &p, &l)) == 1) {
        if (w == 2) switch (f) {
        case 1: parse_caddr(p, l, s.resolver_address, sizeof s.resolver_address, NULL); break;
        case 2: parse_caddr(p, l, s.protocol_contract, sizeof s.protocol_contract, NULL); break;
        case 3: s.public_key_len = l > sizeof s.public_key ? sizeof s.public_key : l; memcpy(s.public_key, p, s.public_key_len); break;
        case 4: s.signature_len = l > sizeof s.signature ? sizeof s.signature : l; memcpy(s.signature, p, s.signature_len); break;
        default: break;
        } else if (w == 0 && f == 5) s.validity_deadline = v;
    }
    if (rc < 0 || !s.signature_len) { LG("[escrow] malformed ResolverAddressSignedEvent"); return 1; }
    int slot = -1;
    for (int i = 0; i < MAX_SIGS; i++) {
        if (g_sig_used[i] && !strcmp(g_sigs[i].resolver_address, s.resolver_address) &&
            !strcmp(g_sigs[i].protocol_contract, s.protocol_contract)) { slot = i; break; }
        if (!g_sig_used[i] && slot < 0) slot = i;
    }
    if (slot >= 0) { g_sigs[slot] = s; g_sig_used[slot] = 1; }
    LG("[escrow] ADDRESS SIGNED resolver=%s contract=%s sig=%zuB pub=%zuB valid_until=%llu",
       s.resolver_address, s.protocol_contract, s.signature_len, s.public_key_len, (unsigned long long)s.validity_deadline);
    if (g_hooks.on_signed) g_hooks.on_signed(&s);
    return 1;
}

int escrow_handle_event(uint32_t field, const uint8_t *d, size_t n) {
    switch (field) {
    case 11: return on_address_signed(d, n);
    case 30: return on_order_updated(d, n);
    case 31: return on_order_closed(d, n);
    case 40: return on_execution_updated(d, n);
    default: return 0;
    }
}

void escrow_init(escrow_log_fn logger, const escrow_hooks_t *hooks) {
    g_log = logger;
    memset(&g_hooks, 0, sizeof g_hooks);
    if (hooks) g_hooks = *hooks;
}

const escrow_order_t *escrow_find(const char *quote_id) {
    for (int i = 0; i < MAX_ORDERS; i++)
        if (g_order_used[i] && !strcmp(g_orders[i].q.quote_id, quote_id)) return &g_orders[i];
    return NULL;
}
int escrow_open_count(void) { int c = 0; for (int i = 0; i < MAX_ORDERS; i++) c += g_order_used[i]; return c; }
const char *escrow_last_ton_contract(void) { return g_last_ton_contract[0] ? g_last_ton_contract : NULL; }

/* ------------------------------------------------------------ sign cache */
static void caddr_msg(pbw_t *w, uint32_t f, uint32_t chain_field, const char *addr) {
    uint8_t tmp[160]; pbw_t a; pbw_init(&a, tmp, sizeof tmp);
    pbw_str(&a, chain_field, addr);
    if (a.err) { w->err = 1; return; }
    pbw_bytes(w, f, tmp, a.len);
}

size_t escrow_build_sign_request(uint8_t *buf, size_t cap, uint64_t seqno, uint32_t chain_field,
                                 const char *resolver_addr, const char *protocol_contract) {
    uint8_t body[400]; pbw_t b; pbw_init(&b, body, sizeof body);
    caddr_msg(&b, 1, chain_field, resolver_addr);
    caddr_msg(&b, 2, chain_field, protocol_contract);
    pbw_t m; pbw_init(&m, buf, cap);
    pbw_u64(&m, 1, seqno);
    pbw_bytes(&m, 11, body, b.len);
    return (b.err || m.err) ? 0 : m.len;
}

const escrow_signed_t *escrow_sign_get(const char *rk, const char *ck, uint64_t now_s, uint64_t margin_s) {
    for (int i = 0; i < MAX_SIGS; i++)
        if (g_sig_used[i] && !strcmp(g_sigs[i].resolver_address, rk) && !strcmp(g_sigs[i].protocol_contract, ck))
            return g_sigs[i].validity_deadline > now_s + margin_s ? &g_sigs[i] : NULL;
    return NULL;
}
int escrow_sign_refresh_due(const char *rk, const char *ck, uint64_t now_s, uint64_t margin_s) {
    return escrow_sign_get(rk, ck, now_s, margin_s) == NULL;
}

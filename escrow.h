/* escrow.h - order/execution/sign-address layer, independent of the transport.
 *
 * The transport (omniston_resolver.c) hands raw ResolverEvent sub-messages to escrow_handle_event()
 * and gets back parsed structs through hooks. The actual settlement logic (building the escrow / HTLC
 * transactions, Highload V3 sends) plugs in through escrow_hooks_t - nothing here touches the network.
 *
 * All strings are copied; structs passed to hooks are only valid during the hook call. */
#ifndef ESCROW_H
#define ESCROW_H
#include <stddef.h>
#include <stdint.h>
#include "pb.h"

#define ESC_ADDR  128
#define ESC_ASSET 112
#define ESC_ID    80
#define ESC_UNITS 48
#define ESC_BLOB  1024

typedef struct {                       /* Quote (types/quote.proto) incl. OrderSettlementData */
    char rfq_id[ESC_ID], quote_id[ESC_ID], resolver_id[ESC_ADDR], resolver_name[64];
    char in_asset[ESC_ASSET], out_asset[ESC_ASSET];
    char input_units[ESC_UNITS], output_units[ESC_UNITS];
    char integrator_fee_units[ESC_UNITS], protocol_fee_units[ESC_UNITS];
    uint64_t quote_timestamp;
    int has_order_settlement;
    char src_protocol_contract[ESC_ADDR], src_wrapped_native[ESC_ADDR], src_initial_resolver[ESC_ADDR];
    char dst_protocol_contract[ESC_ADDR], dst_wrapped_native[ESC_ADDR];
    char resolver_sends_units[ESC_UNITS];
    uint64_t trade_start_deadline, exclusivity_timeout;
    uint32_t integrator_fee_pips, protocol_fee_pips;
} escrow_quote_t;

typedef struct {                       /* position oneof + optional blobs shared by order/execution events */
    char escrow_address[ESC_ADDR];     /* "" if absent */
    int  has_signed_order; size_t signed_order_len;   /* EVM signed order: only presence/size kept */
    uint8_t order_details[ESC_BLOB]; size_t order_details_len;     /* serialized_order_details (HtlcOrderDetails) */
    uint8_t dst_condition_code[ESC_BLOB]; size_t dst_condition_code_len; /* TON HTLC dst condition code cell */
    int order_details_truncated, dst_code_truncated;
} escrow_position_t;

typedef struct {                       /* OrderUpdatedEvent (field 30) */
    escrow_quote_t q;
    char remaining_input_units[ESC_UNITS];
    uint64_t remaining_secrets, cancellation_available_timestamp;
    char exclusive_resolver[ESC_ADDR];
    escrow_position_t pos;
} escrow_order_t;

typedef struct {                       /* Execution (types/order.proto) */
    uint64_t index;
    char input_units[ESC_UNITS], output_units[ESC_UNITS], resolver_sends_units[ESC_UNITS];
    uint8_t secret_hash[64]; size_t secret_hash_len;
    char resolver_id[ESC_ADDR], resolver_name[64];
    char input_position_address[ESC_ADDR], src_resolver_address[ESC_ADDR], output_position_address[ESC_ADDR];
    int input_phase, output_phase;     /* ExecutionPhase, -1 if absent */
    uint64_t in_private_completion, in_public_completion, in_private_rollback, in_public_rollback; /* ts, 0 = absent */
    uint64_t out_private_completion, out_public_completion, out_private_rollback, out_public_rollback;
} escrow_execution_t;

typedef struct {                       /* ExecutionUpdatedEvent (field 40) */
    escrow_quote_t q;
    escrow_execution_t ex;
    uint8_t secret[64]; size_t secret_len;   /* revealed secret, if the event carries it */
    escrow_position_t pos;
} escrow_exec_event_t;

typedef struct {                       /* ResolverAddressSignedEvent (field 11) */
    char resolver_address[ESC_ADDR], protocol_contract[ESC_ADDR];
    uint8_t public_key[64]; size_t public_key_len;
    uint8_t signature[128]; size_t signature_len;
    uint64_t validity_deadline;        /* unix seconds */
} escrow_signed_t;

typedef struct {                       /* implement what you need, leave others NULL */
    void (*on_order)(const escrow_order_t *o, int is_new);
    void (*on_execution)(const escrow_exec_event_t *e);
    void (*on_closed)(const char *quote_id);
    void (*on_signed)(const escrow_signed_t *s);
} escrow_hooks_t;

typedef void (*escrow_log_fn)(const char *fmt, ...);
void escrow_init(escrow_log_fn logger, const escrow_hooks_t *hooks);   /* hooks may be NULL: default = log only */

/* Feed one ResolverEvent oneof member. Returns 1 if handled (fields 11, 30, 31, 40), 0 otherwise. */
int escrow_handle_event(uint32_t field, const uint8_t *d, size_t n);

/* ---- state of open orders (keyed by quote_id) ---- */
const escrow_order_t *escrow_find(const char *quote_id);
int escrow_open_count(void);
const char *escrow_last_ton_contract(void);  /* raw TON address (without "ton:") from latest OrderUpdated, or NULL */
const char *escrow_phase_name(int phase);

/* ---- resolver-address signature cache ---- */
/* Build ResolverRequest{seqno, sign_resolver_address{resolver_address, protocol_contract_address}} (no gRPC frame).
 * chain_field = ChainAddress oneof field (50 = ton). Returns bytes written or 0 on overflow. */
size_t escrow_build_sign_request(uint8_t *buf, size_t cap, uint64_t seqno, uint32_t chain_field,
                                 const char *resolver_addr, const char *protocol_contract);
/* Cached signature still valid for at least margin_s seconds, else NULL. Keys are "ton:<addr>" strings. */
const escrow_signed_t *escrow_sign_get(const char *resolver_key, const char *contract_key,
                                       uint64_t now_s, uint64_t margin_s);
/* 1 if a (re)request is due: nothing cached or it expires within margin_s. */
int escrow_sign_refresh_due(const char *resolver_key, const char *contract_key, uint64_t now_s, uint64_t margin_s);

#endif

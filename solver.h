/* solver.h - the single seam between the network client and your routing engine. */
#ifndef SOLVER_H
#define SOLVER_H
#include <stdint.h>

typedef unsigned __int128 u128;

typedef struct {
    char rfq_id[80];
    char in_asset[112];   /* what the resolver RECEIVES, e.g. "ton:native", "ton:EQ...", "bnb:0x..." */
    char out_asset[112];  /* what the resolver SENDS */
    int  has_receives;    /* trader fixed the input amount  */
    u128 receives;
    int  has_sends;       /* trader fixed the output amount */
    u128 sends;
    int64_t validity_s;   /* quote_validity_timeout from protocol params, 0 if absent */
} rfq_t;

/* Fill *receives and *sends (integer asset units) and return 0 to quote.
 * Return non-zero to decline (no update_quote is sent).
 * Rules from the protocol: if rfq->has_receives, copy it into *receives and
 * compute *sends; if rfq->has_sends, copy it into *sends and compute *receives. */
int solver_quote(const rfq_t *rfq, u128 *receives, u128 *sends);

#endif

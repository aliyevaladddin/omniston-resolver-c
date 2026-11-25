/* solver_demo.c - toy solver used ONLY for the local mock-server test.
 * Quotes a flat 0.3% fee. Not a real price. */
#include "solver.h"

int solver_quote(const rfq_t *r, u128 *receives, u128 *sends) {
    if (r->has_receives) { *receives = r->receives; *sends = r->receives * 997 / 1000; return 0; }
    if (r->has_sends)    { *sends = r->sends;       *receives = r->sends * 1000 / 997 + 1; return 0; }
    return 1;
}

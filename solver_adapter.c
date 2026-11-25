/* solver_adapter.c - TEMPLATE. Replace the body with a call into your C engine
 * (the one that does the indexed route search). It declines every RFQ until you do. */
#include "solver.h"

int solver_quote(const rfq_t *rfq, u128 *receives, u128 *sends) {
    (void)rfq; (void)receives; (void)sends;
    /* Example shape (adapt to your engine's real API):
     *
     *   uint64_t out;
     *   if (rfq->has_receives) {
     *       if (engine_best_out(rfq->in_asset, rfq->out_asset, (uint64_t)rfq->receives, &out)) return 1;
     *       *receives = rfq->receives; *sends = out; return 0;
     *   }
     *   return 1;
     *
     * Note: amounts are u128 here; your engine may use u64. Reject (return 1) anything that
     * does not fit instead of truncating.
     */
    return 1;
}

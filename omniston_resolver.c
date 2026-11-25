/*
 * omniston_resolver.c - STON.fi Omniston resolver client (protocol v1beta8) in C.
 *
 * C port of the Node.js client: gRPC bidirectional stream ResolverRpc.Open over
 * HTTP/2 (nghttp2) + TLS (OpenSSL), Ed25519 authentication, quote_requested ->
 * solver_quote() -> update_quote.  No allocation on the quote path.
 *
 * Config (environment, same names as the Node client):
 *   OMNISTON_GRPC_ENDPOINT   host:port            default omni-grpc-sandbox.ston.fi:443
 *   OMNISTON_KEYS_PATH       JSON {"publicKey":hex,"privateKey":hex}
 *   OMNISTON_STAKE_ADDRESS   stake address (goes into the signed payload)
 *   OMNISTON_RESOLVER_ADDRESS  your TON resolver address (used in update_quote)
 *   OMNISTON_EVM_ADDRESS     optional, for non-TON legs
 *   OMNISTON_INSECURE=1      plain HTTP/2 without TLS (local mock server ONLY)
 *   OMNISTON_IDLE_TIMEOUT_S  drop the stream if silent this long (default 120)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "pb.h"
#include "pbtypes.h"
#include "solver.h"
#include "escrow.h"

#define MAX_MSG   (1u << 20)
#define OUTQ_CAP  (1u << 18)
#define RPC_PATH  "/stonfi.omni.v1beta8.ResolverRpc/Open"

/* ------------------------------------------------------------------ config */
static char g_host[256], g_port[16] = "443";
static int  g_insecure, g_idle_s = 120;
static const char *g_stake, *g_resolver_ton, *g_resolver_evm;
static uint8_t g_pub[32], g_seed[32];
static volatile sig_atomic_t g_stop;

static void vlogf_(const char *tag, const char *fmt, va_list ap) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    char tb[32]; struct tm tm; gmtime_r(&ts.tv_sec, &tm);
    strftime(tb, sizeof tb, "%H:%M:%S", &tm);
    fprintf(stderr, "%s.%03ld [%s] ", tb, ts.tv_nsec / 1000000, tag);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}
static void logf_(const char *tag, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void logf_(const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vlogf_(tag, fmt, ap); va_end(ap);
}
static void esc_log(const char *fmt, ...) {      /* logger handed to escrow.c */
    va_list ap; va_start(ap, fmt); vlogf_("$", fmt, ap); va_end(ap);
}
#define LOG(...) logf_("*", __VA_ARGS__)
#define ERR(...) logf_("!", __VA_ARGS__)

static uint64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static uint64_t mono_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------- keys (JSON) */
static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* find "name":"hex" and decode up to maxn bytes; returns decoded length or -1 */
static int json_hex(const char *js, const char *name, uint8_t *out, int maxn) {
    char pat[64]; snprintf(pat, sizeof pat, "\"%s\"", name);
    const char *p = strstr(js, pat);
    if (!p) return -1;
    p = strchr(p + strlen(pat), ':');
    if (!p) return -1;
    p = strchr(p, '"');
    if (!p) return -1;
    p++;
    int n = 0;
    while (hexval(p[0]) >= 0 && hexval(p[1]) >= 0) {
        if (n < maxn) out[n] = (uint8_t)(hexval(p[0]) << 4 | hexval(p[1]));
        n++; p += 2;
    }
    return n;
}
static int load_keys(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { ERR("keys file not found: %s", path); return -1; }
    char js[4096]; size_t n = fread(js, 1, sizeof js - 1, f); fclose(f); js[n] = 0;
    uint8_t priv[64];
    int pl = json_hex(js, "privateKey", priv, sizeof priv);
    int ql = json_hex(js, "publicKey", g_pub, sizeof g_pub);
    OPENSSL_cleanse(js, sizeof js);
    if (ql != 32) { ERR("publicKey must be 32 bytes hex"); return -1; }
    if (pl != 32 && pl != 64) { ERR("privateKey must be 32 (seed) or 64 (seed+pub) bytes hex"); return -1; }
    memcpy(g_seed, priv, 32);            /* if 64 bytes, the first 32 are the seed */
    OPENSSL_cleanse(priv, sizeof priv);
    return 0;
}
static int ed25519_sign(const uint8_t *msg, size_t n, uint8_t sig[64]) {
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, g_seed, 32);
    if (!k) return -1;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    size_t sl = 64; int ok = 0;
    if (c && EVP_DigestSignInit(c, NULL, NULL, NULL, k) == 1 &&
        EVP_DigestSign(c, sig, &sl, msg, n) == 1 && sl == 64) ok = 1;
    EVP_MD_CTX_free(c); EVP_PKEY_free(k);
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------ u128 <-> str */
static int u128_parse(const uint8_t *s, size_t n, u128 *out) {
    if (n == 0 || n > 39) return -1;
    u128 v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        u128 d = (u128)(s[i] - '0');
        if (v > (~(u128)0 - d) / 10) return -1;
        v = v * 10 + d;
    }
    *out = v; return 0;
}
static int u128_fmt(u128 v, char *buf) {   /* buf >= 40 */
    char t[40]; int n = 0;
    do { t[n++] = (char)('0' + (int)(v % 10)); v /= 10; } while (v);
    for (int i = 0; i < n; i++) buf[i] = t[n - 1 - i];
    buf[n] = 0; return n;
}

/* --------------------------------------------------------------- messages */
static int parse_quote_requested(const uint8_t *d, size_t n, rfq_t *q, uint32_t *in_chain, uint32_t *out_chain) {
    memset(q, 0, sizeof *q);
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l; int rc;
    *in_chain = *out_chain = 0;
    while ((rc = pbr_next(&r, &f, &w, &v, &p, &l)) == 1) {
        if (f == 1 && w == 2) snprintf(q->rfq_id, sizeof q->rfq_id, "%.*s", (int)l, (const char *)p);
        else if (f == 2 && w == 2) {                           /* QuoteRequest */
            pbr_t m; pbr_init(&m, p, l);
            uint32_t f2, w2; uint64_t v2; const uint8_t *p2; size_t l2;
            while (pbr_next(&m, &f2, &w2, &v2, &p2, &l2) == 1) {
                if (w2 != 2) continue;
                if (f2 == 1) parse_asset(p2, l2, q->in_asset, sizeof q->in_asset, in_chain);
                else if (f2 == 2) parse_asset(p2, l2, q->out_asset, sizeof q->out_asset, out_chain);
            }
        } else if (f == 10 && w == 2) { q->has_receives = (u128_parse(p, l, &q->receives) == 0); }
        else if (f == 11 && w == 2) { q->has_sends = (u128_parse(p, l, &q->sends) == 0); }
        else if (f == 20 && w == 2) {                          /* ProtocolParams */
            pbr_t m; pbr_init(&m, p, l);
            uint32_t f2, w2; uint64_t v2; const uint8_t *p2; size_t l2;
            while (pbr_next(&m, &f2, &w2, &v2, &p2, &l2) == 1)
                if (f2 == 20 && w2 == 0) q->validity_s = pb_zigzag(v2);
        }
    }
    return rc < 0 ? -1 : 0;
}

/* write field `f` as a ChainAddress submessage */
static void pbw_chain_addr(pbw_t *w, uint32_t f, uint32_t chain_field, const char *addr) {
    uint8_t tmp[128]; pbw_t a; pbw_init(&a, tmp, sizeof tmp);
    pbw_str(&a, chain_field, addr);
    if (a.err) { w->err = 1; return; }
    pbw_bytes(w, f, tmp, a.len);
}

/* --------------------------------------------------------------- transport */
typedef struct {
    int fd; SSL_CTX *ctx; SSL *ssl;
    nghttp2_session *sess; int32_t stream;
    uint8_t outq[OUTQ_CAP]; size_t out_head, out_tail;
    uint8_t in[MAX_MSG + 5]; size_t in_len;
    uint64_t seqno, last_rx_ms, last_sign_req_ms;
    int connected, want_pollout, grpc_status, headers_done, closed;
    char grpc_msg[256];
} conn_t;

static int outq_put_msg(conn_t *c, const uint8_t *msg, size_t n) {
    if (c->out_head == c->out_tail) c->out_head = c->out_tail = 0;
    if (c->out_tail + 5 + n > OUTQ_CAP) {
        memmove(c->outq, c->outq + c->out_head, c->out_tail - c->out_head);
        c->out_tail -= c->out_head; c->out_head = 0;
        if (c->out_tail + 5 + n > OUTQ_CAP) return -1;
    }
    uint8_t *o = c->outq + c->out_tail;
    o[0] = 0; o[1] = (uint8_t)(n >> 24); o[2] = (uint8_t)(n >> 16); o[3] = (uint8_t)(n >> 8); o[4] = (uint8_t)n;
    memcpy(o + 5, msg, n);
    c->out_tail += 5 + n;
    nghttp2_session_resume_data(c->sess, c->stream);
    return 0;
}

static nghttp2_ssize body_read_cb(nghttp2_session *s, int32_t sid, uint8_t *buf, size_t len,
                                  uint32_t *flags, nghttp2_data_source *src, void *ud) {
    (void)s; (void)sid; (void)flags; (void)src;
    conn_t *c = ud;
    size_t avail = c->out_tail - c->out_head;
    if (avail == 0) return NGHTTP2_ERR_DEFERRED;
    size_t n = avail < len ? avail : len;
    memcpy(buf, c->outq + c->out_head, n);
    c->out_head += n;
    return (nghttp2_ssize)n;
}

static ssize_t io_write(conn_t *c, const uint8_t *d, size_t n) {
    if (g_insecure) {
        ssize_t r = send(c->fd, d, n, MSG_NOSIGNAL);
        if (r < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
        return r;
    }
    int r = SSL_write(c->ssl, d, (int)n);
    if (r > 0) return r;
    int e = SSL_get_error(c->ssl, r);
    return (e == SSL_ERROR_WANT_WRITE || e == SSL_ERROR_WANT_READ) ? 0 : -1;
}
static ssize_t io_read(conn_t *c, uint8_t *d, size_t n) {   /* 0 = would block, -1 = closed/error */
    if (g_insecure) {
        ssize_t r = recv(c->fd, d, n, 0);
        if (r == 0) return -1;
        if (r < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
        return r;
    }
    int r = SSL_read(c->ssl, d, (int)n);
    if (r > 0) return r;
    int e = SSL_get_error(c->ssl, r);
    return (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) ? 0 : -1;
}

static nghttp2_ssize send_cb(nghttp2_session *s, const uint8_t *d, size_t n, int fl, void *ud) {
    (void)s; (void)fl;
    conn_t *c = ud;
    ssize_t r = io_write(c, d, n);
    if (r < 0) return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (r == 0) { c->want_pollout = 1; return NGHTTP2_ERR_WOULDBLOCK; }
    return r;
}

/* --------------------------------------------------------- event handling */
static void send_connect(conn_t *c) {
    uint8_t payload[160]; pbw_t w; pbw_init(&w, payload, sizeof payload);
    pbw_u64(&w, 1, now_ms());
    pbw_str(&w, 2, g_stake);
    uint8_t sig[64];
    if (w.err || ed25519_sign(payload, w.len, sig) != 0) { ERR("failed to sign auth payload"); c->closed = 1; return; }
    uint8_t cr[400]; pbw_t cw; pbw_init(&cw, cr, sizeof cr);
    pbw_bytes(&cw, 1, payload, w.len);
    pbw_bytes(&cw, 2, g_pub, 32);
    pbw_bytes(&cw, 3, sig, 64);
    uint8_t msg[512]; pbw_t m; pbw_init(&m, msg, sizeof msg);
    pbw_u64(&m, 1, ++c->seqno);                 /* ResolverRequest.seqno */
    pbw_bytes(&m, 10, cr, cw.len);              /* connect */
    if (m.err || outq_put_msg(c, msg, m.len) != 0) { ERR("connect enqueue failed"); c->closed = 1; return; }
    LOG("ConnectRequest sent (stake %s)", g_stake);
}

static void send_update_quote(conn_t *c, const rfq_t *q, u128 recv, u128 sends,
                              uint32_t in_chain, uint32_t out_chain) {
    const char *src = in_chain == 50 ? g_resolver_ton : g_resolver_evm;
    const char *dst = out_chain == 50 ? g_resolver_ton : g_resolver_evm;
    if (!src || !dst) { LOG("no resolver address for chain, skipping %s", q->rfq_id); return; }
    char rs[40], ss[40]; u128_fmt(recv, rs); u128_fmt(sends, ss);
    uint8_t quote[512]; pbw_t qw; pbw_init(&qw, quote, sizeof quote);
    pbw_chain_addr(&qw, 1, in_chain, src);
    pbw_str(&qw, 2, rs);
    pbw_chain_addr(&qw, 3, out_chain, dst);
    pbw_str(&qw, 4, ss);
    pbw_u64(&qw, 5, now_ms() / 1000 + (q->validity_s > 0 ? (uint64_t)q->validity_s : 30));
    uint8_t uq[640]; pbw_t uw; pbw_init(&uw, uq, sizeof uq);
    pbw_str(&uw, 1, q->rfq_id);
    pbw_bytes(&uw, 10, quote, qw.len);
    uint8_t msg[768]; pbw_t m; pbw_init(&m, msg, sizeof msg);
    pbw_u64(&m, 1, ++c->seqno);
    pbw_bytes(&m, 20, uq, uw.len);              /* update_quote */
    if (qw.err || uw.err || m.err || outq_put_msg(c, msg, m.len) != 0) ERR("update_quote encode/enqueue failed");
}

static char g_sign_resolver[ESC_ADDR], g_sign_contract[ESC_ADDR];
static const char *g_protocol_contract;

/* ask the server to sign (resolver, protocol contract) when nothing valid is cached; re-ask <=1/10 s */
static void maybe_request_sign(conn_t *c) {
    const char *contract = g_protocol_contract ? g_protocol_contract : escrow_last_ton_contract();
    if (!c->connected || !contract || !contract[0]) return;
    uint64_t t = mono_ms();
    if (c->last_sign_req_ms && t - c->last_sign_req_ms < 10000) return;
    snprintf(g_sign_contract, sizeof g_sign_contract, "ton:%s", contract);
    if (!escrow_sign_refresh_due(g_sign_resolver, g_sign_contract, now_ms() / 1000, 60)) return;
    uint8_t msg[512];
    size_t n = escrow_build_sign_request(msg, sizeof msg, ++c->seqno, 50, g_resolver_ton, contract);
    if (n && outq_put_msg(c, msg, n) == 0) { c->last_sign_req_ms = t; LOG("SignResolverAddress requested (contract %s)", contract); }
    else ERR("sign request enqueue failed");
}

static void on_event(conn_t *c, const uint8_t *d, size_t n) {
    pbr_t r; pbr_init(&r, d, n);
    uint32_t f, w; uint64_t v; const uint8_t *p; size_t l; int rc;
    while ((rc = pbr_next(&r, &f, &w, &v, &p, &l)) == 1) {
        if (w != 2) continue;                          /* seqno/reply_to are varints: ignored */
        switch (f) {
        case 10:
            c->connected = 1; LOG("CONNECTED and authenticated; waiting for RFQs"); break;
        case 100: break;                               /* keep_alive */
        case 20: {                                     /* quote_requested */
            rfq_t q; uint32_t ic, oc;
            if (parse_quote_requested(p, l, &q, &ic, &oc) != 0) { ERR("malformed quote_requested"); break; }
            u128 recv = 0, sends = 0;
            uint64_t t0 = mono_ms();
            int dec = solver_quote(&q, &recv, &sends);
            char rb[40] = "0", sb[40] = "0";
            if (!dec) { u128_fmt(recv, rb); u128_fmt(sends, sb); }
            LOG("RFQ %s %s -> %s %s (solver %s, in=%s out=%s, %llu ms)", q.rfq_id, q.in_asset, q.out_asset,
                q.has_receives ? "recv fixed" : "sends fixed", dec ? "declined" : "quoted",
                rb, sb, (unsigned long long)(mono_ms() - t0));
            if (!dec) send_update_quote(c, &q, recv, sends, ic, oc);
            break;
        }
        case 21: {                                     /* quote_request_cancelled */
            pbr_t m; pbr_init(&m, p, l); char rfq[80] = "";
            uint32_t f2, w2; uint64_t v2; const uint8_t *p2; size_t l2;
            while (pbr_next(&m, &f2, &w2, &v2, &p2, &l2) == 1)
                if (f2 == 1 && w2 == 2) snprintf(rfq, sizeof rfq, "%.*s", (int)l2, (const char *)p2);
            LOG("RFQ cancelled rfq_id=%s", rfq); break;
        }
        case 11: case 30: case 31: case 40:             /* signed address / order / closed / execution */
            escrow_handle_event(f, p, l);
            if (f == 30) maybe_request_sign(c);
            break;
        case 22: {                                     /* quote_accepted */
            pbr_t m; pbr_init(&m, p, l); char rfq[80] = "", qid[80] = "";
            uint32_t f2, w2; uint64_t v2; const uint8_t *p2; size_t l2;
            while (pbr_next(&m, &f2, &w2, &v2, &p2, &l2) == 1) if (w2 == 2) {
                if (f2 == 1) snprintf(rfq, sizeof rfq, "%.*s", (int)l2, (const char *)p2);
                if (f2 == 2) snprintf(qid, sizeof qid, "%.*s", (int)l2, (const char *)p2);
            }
            LOG("QUOTE ACCEPTED rfq_id=%s quote_id=%s", rfq, qid); break;
        }
        case 23: {                                     /* quote_rejected */
            pbr_t m; pbr_init(&m, p, l); char rfq[80] = "", msg[160] = ""; uint64_t code = 0;
            uint32_t f2, w2; uint64_t v2; const uint8_t *p2; size_t l2;
            while (pbr_next(&m, &f2, &w2, &v2, &p2, &l2) == 1) {
                if (f2 == 1 && w2 == 2) snprintf(rfq, sizeof rfq, "%.*s", (int)l2, (const char *)p2);
                else if (f2 == 2 && w2 == 0) code = v2;
                else if (f2 == 3 && w2 == 2) snprintf(msg, sizeof msg, "%.*s", (int)l2, (const char *)p2);
            }
            LOG("quote rejected rfq_id=%s code=%llu %s", rfq, (unsigned long long)code, msg); break;
        }
        default: LOG("event field %u (len %zu) ignored", f, l);
        }
    }
    if (rc < 0) ERR("malformed ResolverEvent");
}

/* gRPC framing: accumulate DATA, peel off length-prefixed messages */
static int on_chunk(nghttp2_session *s, uint8_t fl, int32_t sid, const uint8_t *d, size_t n, void *ud) {
    (void)s; (void)fl; (void)sid;
    conn_t *c = ud;
    c->last_rx_ms = mono_ms();
    if (c->in_len + n > sizeof c->in) { ERR("message too large"); return NGHTTP2_ERR_CALLBACK_FAILURE; }
    memcpy(c->in + c->in_len, d, n); c->in_len += n;
    size_t off = 0;
    while (c->in_len - off >= 5) {
        uint32_t len = (uint32_t)c->in[off + 1] << 24 | c->in[off + 2] << 16 | c->in[off + 3] << 8 | c->in[off + 4];
        if (len > MAX_MSG) return NGHTTP2_ERR_CALLBACK_FAILURE;
        if (c->in[off] != 0) { ERR("compressed gRPC message not supported"); return NGHTTP2_ERR_CALLBACK_FAILURE; }
        if (c->in_len - off - 5 < len) break;
        on_event(c, c->in + off + 5, len);
        off += 5 + len;
    }
    if (off) { memmove(c->in, c->in + off, c->in_len - off); c->in_len -= off; }
    return 0;
}
static int on_header(nghttp2_session *s, const nghttp2_frame *fr, const uint8_t *name, size_t nl,
                     const uint8_t *val, size_t vl, uint8_t fl, void *ud) {
    (void)s; (void)fr; (void)fl;
    conn_t *c = ud;
    if (nl == 11 && !memcmp(name, "grpc-status", 11)) { char t[16]; snprintf(t, sizeof t, "%.*s", (int)(vl < 15 ? vl : 15), (const char *)val); c->grpc_status = atoi(t); }
    if (nl == 12 && !memcmp(name, "grpc-message", 12)) snprintf(c->grpc_msg, sizeof c->grpc_msg, "%.*s", (int)vl, (const char *)val);
    return 0;
}
static int on_close(nghttp2_session *s, int32_t sid, uint32_t code, void *ud) {
    (void)s; (void)sid;
    conn_t *c = ud;
    LOG("stream closed (h2 error code %u, grpc-status %d %s)", code, c->grpc_status, c->grpc_msg);
    c->closed = 1;
    return 0;
}

/* ------------------------------------------------------------- connection */
static int tcp_connect(void) {
    struct addrinfo h = {0}, *res, *a; h.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_host, g_port, &h, &res) != 0) { ERR("DNS failed for %s", g_host); return -1; }
    int fd = -1;
    for (a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, a->ai_addr, a->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { ERR("TCP connect failed"); return -1; }
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    return fd;
}

static int tls_start(conn_t *c) {
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) return -1;
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    SSL_CTX_set_default_verify_paths(c->ctx);
    SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
    static const unsigned char alpn[] = {2, 'h', '2'};
    SSL_CTX_set_alpn_protos(c->ctx, alpn, sizeof alpn);
    c->ssl = SSL_new(c->ctx);
    SSL_set_fd(c->ssl, c->fd);
    SSL_set_tlsext_host_name(c->ssl, g_host);
    SSL_set1_host(c->ssl, g_host);
    if (SSL_connect(c->ssl) != 1) { ERR("TLS handshake failed"); ERR_print_errors_fp(stderr); return -1; }
    const unsigned char *pr; unsigned int pl;
    SSL_get0_alpn_selected(c->ssl, &pr, &pl);
    if (pl != 2 || memcmp(pr, "h2", 2)) { ERR("server did not negotiate h2"); return -1; }
    return 0;
}

static void conn_free(conn_t *c) {
    if (c->sess) nghttp2_session_del(c->sess);
    if (c->ssl) SSL_free(c->ssl);
    if (c->ctx) SSL_CTX_free(c->ctx);
    if (c->fd >= 0) close(c->fd);
}

static void run_once(conn_t *c) {
    memset(c, 0, sizeof *c); c->fd = -1;
    LOG("connecting to %s:%s (%s)", g_host, g_port, g_insecure ? "PLAINTEXT h2c - test mode" : "TLS");
    c->fd = tcp_connect();
    if (c->fd < 0) return;
    if (!g_insecure && tls_start(c) != 0) { conn_free(c); return; }
    fcntl(c->fd, F_SETFL, fcntl(c->fd, F_GETFL) | O_NONBLOCK);

    nghttp2_session_callbacks *cb; nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_send_callback2(cb, send_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_chunk);
    nghttp2_session_callbacks_set_on_header_callback(cb, on_header);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_close);
    nghttp2_session_client_new(&c->sess, cb, c);
    nghttp2_session_callbacks_del(cb);

    nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 1 << 20}};
    nghttp2_submit_settings(c->sess, NGHTTP2_FLAG_NONE, iv, 1);
    nghttp2_session_set_local_window_size(c->sess, NGHTTP2_FLAG_NONE, 0, 1 << 20);

    char auth[300]; snprintf(auth, sizeof auth, "%s:%s", g_host, g_port);
    nghttp2_nv hdr[] = {
#define NV(n, v) {(uint8_t *)n, (uint8_t *)(v), sizeof(n) - 1, strlen(v), NGHTTP2_NV_FLAG_NONE}
        NV(":method", "POST"), NV(":scheme", g_insecure ? "http" : "https"), NV(":path", RPC_PATH),
        NV(":authority", auth), NV("content-type", "application/grpc"), NV("te", "trailers"),
        NV("user-agent", "omniston-resolver-c/0.1"),
    };
    nghttp2_data_provider2 prov = {.source = {.ptr = c}, .read_callback = body_read_cb};
    c->stream = nghttp2_submit_request2(c->sess, NULL, hdr, sizeof hdr / sizeof hdr[0], &prov, NULL);
    if (c->stream < 0) { ERR("submit_request failed"); conn_free(c); return; }
    c->last_rx_ms = mono_ms();
    send_connect(c);

    while (!g_stop && !c->closed && (nghttp2_session_want_read(c->sess) || nghttp2_session_want_write(c->sess))) {
        c->want_pollout = 0;
        maybe_request_sign(c);
        if (nghttp2_session_send(c->sess) != 0) break;
        struct pollfd pf = {c->fd, POLLIN | (c->want_pollout ? POLLOUT : 0), 0};
        int pr = poll(&pf, 1, 1000);
        if (pr < 0 && errno != EINTR) break;
        if (pr > 0 && (pf.revents & (POLLIN | POLLHUP | POLLERR))) {
            uint8_t buf[16384]; int dead = 0;
            for (;;) {
                ssize_t n = io_read(c, buf, sizeof buf);
                if (n < 0) { dead = 1; break; }
                if (n == 0) break;
                if (nghttp2_session_mem_recv2(c->sess, buf, (size_t)n) < 0) { dead = 1; break; }
            }
            if (dead) { LOG("connection closed by peer"); break; }
        }
        if (mono_ms() - c->last_rx_ms > (uint64_t)g_idle_s * 1000) { ERR("idle timeout, reconnecting"); break; }
    }
    conn_free(c);
}

static void on_sig(int s) { (void)s; g_stop = 1; }

int main(void) {
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig); signal(SIGPIPE, SIG_IGN); signal(SIGHUP, SIG_IGN);
    const char *ep = getenv("OMNISTON_GRPC_ENDPOINT"); if (!ep) ep = "omni-grpc-sandbox.ston.fi:443";
    const char *colon = strrchr(ep, ':');
    if (colon) { snprintf(g_host, sizeof g_host, "%.*s", (int)(colon - ep), ep); snprintf(g_port, sizeof g_port, "%s", colon + 1); }
    else snprintf(g_host, sizeof g_host, "%s", ep);
    const char *kp = getenv("OMNISTON_KEYS_PATH"); if (!kp) kp = "resolver_keys.json";
    g_stake = getenv("OMNISTON_STAKE_ADDRESS");
    g_resolver_ton = getenv("OMNISTON_RESOLVER_ADDRESS");
    g_resolver_evm = getenv("OMNISTON_EVM_ADDRESS");
    g_insecure = getenv("OMNISTON_INSECURE") && getenv("OMNISTON_INSECURE")[0] == '1';
    if (getenv("OMNISTON_IDLE_TIMEOUT_S")) g_idle_s = atoi(getenv("OMNISTON_IDLE_TIMEOUT_S"));
    if (!g_stake || !g_resolver_ton) { ERR("set OMNISTON_STAKE_ADDRESS and OMNISTON_RESOLVER_ADDRESS"); return 1; }
    if (load_keys(kp) != 0) return 1;
    g_protocol_contract = getenv("OMNISTON_PROTOCOL_CONTRACT");   /* TON protocol contract to get the address signed for */
    snprintf(g_sign_resolver, sizeof g_sign_resolver, "ton:%s", g_resolver_ton);
    snprintf(g_sign_contract, sizeof g_sign_contract, "ton:%s", g_protocol_contract ? g_protocol_contract : "");
    escrow_init(esc_log, NULL);
    LOG("omniston resolver (C) target=%s:%s resolver=%s stake=%s", g_host, g_port, g_resolver_ton, g_stake);

    static conn_t conn;
    while (!g_stop) {
        run_once(&conn);
        if (g_stop) break;
        LOG("reconnecting in 3 s");
        for (int i = 0; i < 30 && !g_stop; i++) usleep(100000);
    }
    OPENSSL_cleanse(g_seed, sizeof g_seed);
    return 0;
}

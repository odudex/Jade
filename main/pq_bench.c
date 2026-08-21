/*
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Jade-specific: boot-time SLH-DSA hash benchmark and known-answer tests.
 *
 * Prints, in order:
 *   1. the cost of one SHA-256 compression in four regimes (software, hardware
 *      acquired per call, hardware held via the low-level registers, hardware
 *      held via the public esp_sha_* API), each verified against the software
 *      result before it is timed;
 *   2. NIST ACVP known-answer tests for SLH-DSA-SHA2-128s, run in both the
 *      software and the hardware configuration;
 *   3. KeyGen and SigGen timings in both configurations, for the standard
 *      parameter set and for Jade's reduced one;
 *   4. the cost of releasing and reacquiring the peripheral, which is what the
 *      per-layer progress callback does so that the rest of the device is not
 *      locked out of SHA and AES for the whole signature.
 *
 * Development builds only (CONFIG_JADE_PQ_BENCH).
 */

#ifndef AMALGAMATED_BUILD
#include "pq_bench.h"

#ifdef CONFIG_JADE_PQ_BENCH

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <esp_cpu.h>
#include <esp_timer.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <hal/sha_ll.h>
#include <hal/sha_types.h>
#include <sha/sha_core.h>

#include "slh_dsa/plat_local.h"
#include "slh_dsa/sha2_api.h"
#include "slh_dsa/slh_dsa.h"
#include "pq_hw_sha.h"
#include "slh_dsa/slh_kat_vectors.h"

#include <mbedtls/sha256.h>
#include "shrincs/shrincs.h"
#include "shrincs/uxmss.h"
#include "xmss/xmss_core.h"
#include "xmss/params.h"

#define CPU_MHZ CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ

/* Long enough to average out cache effects, short enough that the 32-bit cycle
 * counter cannot wrap (it wraps every ~17.9 s at 240 MHz; the slowest regime
 * here is ~10k cycles, so 2000 iterations is ~0.08 s). */
#define PROBE_ITERS 2000

typedef void (*slh_compress_fn)(void* v);

static void pqb_noop_cb16(uint16_t value, void* ud);
static void pqb_noop_cb32(uint32_t current, uint32_t total, void* ud);

typedef enum {
    HOLD_NONE = 0, /* regime acquires the peripheral itself, or does not use it */
    HOLD_RAW, /* peripheral taken directly, bypassing the pq_hw_sha wrapper */
    HOLD_WRAPPER, /* taken through pq_hw_sha_begin(), as production does */
} pqb_hold_t;

static void pqb_hold_take(pqb_hold_t hold)
{
    if (hold == HOLD_RAW) {
        esp_sha_acquire_hardware();
        esp_sha_set_mode(SHA2_256);
    } else if (hold == HOLD_WRAPPER) {
        pq_hw_sha_begin();
    }
}

static void pqb_hold_drop(pqb_hold_t hold)
{
    if (hold == HOLD_RAW) {
        esp_sha_release_hardware();
    } else if (hold == HOLD_WRAPPER) {
        pq_hw_sha_end();
    }
}

/* ---------------------------------------------------------------- helpers */

static void pqb_print_hex(const char* label, const uint8_t* p, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

/* Build a context the way SLH-DSA does: sha2_256_init() followed by exactly one
 * 64-byte update leaves s[0..7] holding a genuine midstate with i == 0.  The
 * message block at s[8..23] is then filled with the block to compress. */
static void pqb_make_ctx(sha2_256_t* c, uint8_t seed)
{
    uint8_t block[64];
    uint8_t* mp = (uint8_t*)&c->s[8];

    for (size_t i = 0; i < sizeof(block); ++i) {
        block[i] = (uint8_t)(seed + i * 7u);
    }
    sha2_256_init(c);
    sha2_256_update(c, block, sizeof(block));

    for (size_t i = 0; i < 64; ++i) {
        mp[i] = (uint8_t)(seed * 3u + i * 11u);
    }
}

/* ------------------------------------------------------- compression regimes */

/* Regime A: the reference, unchanged portable C. */
static void pqb_compress_sw(void* v) { sha2_256_compress_sw(v); }

/* Regime B: the naive substitution -- use the accelerator, but acquire and
 * release it around every single hash, exactly as a drop-in replacement built
 * out of a one-shot hardware SHA API would.  Must not be called while the
 * peripheral is held: esp_crypto_sha_aes_lock_acquire() is not re-entrant and
 * would deadlock the task with no panic and no backtrace. */
static void pqb_compress_naive(void* v)
{
    uint32_t* sp = (uint32_t*)v;

    esp_sha_acquire_hardware();
    esp_sha_set_mode(SHA2_256);
    esp_sha_write_digest_state(SHA2_256, sp);
    esp_sha_block(SHA2_256, sp + 8, false);
    esp_sha_read_digest_state(SHA2_256, sp);
    esp_sha_release_hardware();
}

/* Regime C: held peripheral, straight to the low-level registers. */
static void pqb_compress_raw(void* v)
{
    uint32_t* sp = (uint32_t*)v;

    sha_ll_write_digest(SHA2_256, sp, 8); /*  8 stores -> SHA_H_BASE    */
    sha_ll_fill_text_block(sp + 8, 16); /* 16 stores -> SHA_TEXT_BASE */
    sha_ll_continue_block(SHA2_256); /*  1 store                   */
    while (sha_ll_busy()) { } /* poll SHA_BUSY_REG          */
    sha_ll_read_digest(SHA2_256, sp, 8); /*  8 loads  <- SHA_H_BASE    */
}

/* Regime D: held peripheral through the public API. */
static void pqb_compress_held(void* v) { sha2_256_compress_hw(v); }

/* Regime E: the symbol SLH-DSA actually calls, including the guard that falls
 * back to software when the peripheral is not held.  This is what ships. */
static void pqb_compress_dispatch(void* v) { sha2_256_compress(v); }

/* Loop and indirect-call overhead, common to all four regimes above. */
static void pqb_compress_nop(void* v) { (void)v; }

/* --------------------------------------------------------------- the probe */

/* Returns 1 if fn() reproduces the software compression bit for bit. */
static int pqb_verify(const char* name, slh_compress_fn fn, pqb_hold_t hold)
{
    sha2_256_t ref, got;
    int ok = 1;

    for (uint8_t seed = 1; seed <= 8 && ok; ++seed) {
        /* Built before the hold is taken, so it runs in software either way. */
        pqb_make_ctx(&ref, seed);
        memcpy(&got, &ref, sizeof(got));

        sha2_256_compress_sw(ref.s);
        pqb_hold_take(hold);
        fn(got.s);
        pqb_hold_drop(hold);

        if (memcmp(ref.s, got.s, 32) != 0) {
            ok = 0;
            printf("  %-28s MISMATCH at seed %u\n", name, (unsigned)seed);
            pqb_print_hex("    expected ", (const uint8_t*)ref.s, 32);
            pqb_print_hex("    got      ", (const uint8_t*)got.s, 32);
        }
    }
    return ok;
}

/* Mean cycles per call over PROBE_ITERS chained compressions. */
static uint32_t pqb_time(slh_compress_fn fn, pqb_hold_t hold)
{
    sha2_256_t c;
    uint32_t t0, t1;

    pqb_make_ctx(&c, 0x5A);
    pqb_hold_take(hold);

    for (int i = 0; i < 64; ++i) { /* warm caches */
        fn(c.s);
    }

    t0 = esp_cpu_get_cycle_count();
    for (int i = 0; i < PROBE_ITERS; ++i) {
        fn(c.s);
    }
    t1 = esp_cpu_get_cycle_count();

    pqb_hold_drop(hold);

    return (t1 - t0) / PROBE_ITERS;
}

/* Prints x.xx without pulling in floating-point formatting. */
static void pqb_print_ratio(const char* label, uint32_t num, uint32_t den)
{
    const uint32_t hundredths = den ? (uint32_t)(((uint64_t)num * 100u) / den) : 0u;
    printf("%s%u.%02ux", label, (unsigned)(hundredths / 100u), (unsigned)(hundredths % 100u));
}

static void pqb_probe(void)
{
    uint32_t a, b, c, d, e, nop;
    int ok = 1;

    printf("\n--- 1. cost of one SHA-256 compression (midstate + 64B block -> state)\n");

    /* Correctness first: a timing number from a wrong hash is worthless. */
    ok &= pqb_verify("B naive (acquire per call)", pqb_compress_naive, HOLD_NONE);
    ok &= pqb_verify("C held, sha_ll_*", pqb_compress_raw, HOLD_RAW);
    ok &= pqb_verify("D held, esp_sha_*", pqb_compress_held, HOLD_RAW);
    ok &= pqb_verify("E sha2_256_compress, held", pqb_compress_dispatch, HOLD_WRAPPER);
    /* And the guard itself: called with nothing held, the same symbol must
     * quietly produce the software answer rather than abort. */
    ok &= pqb_verify("E sha2_256_compress, unheld", pqb_compress_dispatch, HOLD_NONE);
    if (!ok) {
        printf("  VERIFICATION FAILED - timings below are meaningless\n");
        return;
    }
    printf("  all regimes reproduce the software result bit for bit\n\n");

    nop = pqb_time(pqb_compress_nop, HOLD_NONE);
    a = pqb_time(pqb_compress_sw, HOLD_NONE);
    b = pqb_time(pqb_compress_naive, HOLD_NONE);
    c = pqb_time(pqb_compress_raw, HOLD_RAW);
    d = pqb_time(pqb_compress_held, HOLD_RAW);
    e = pqb_time(pqb_compress_dispatch, HOLD_WRAPPER);

    printf("  regime                            cycles\n");
    printf("  A software sha2_256_compress      %6u\n", (unsigned)a);
    printf("  B hardware, acquired per call     %6u\n", (unsigned)b);
    printf("  C hardware, held, sha_ll_*        %6u\n", (unsigned)c);
    printf("  D hardware, held, esp_sha_*       %6u\n", (unsigned)d);
    printf("  E sha2_256_compress(), held       %6u   <- what SLH-DSA calls\n", (unsigned)e);
    printf("  (loop + indirect call overhead    %6u, included in all five)\n\n", (unsigned)nop);

    pqb_print_ratio("  A/C ", a, c);
    pqb_print_ratio("   B/C ", b, c);
    pqb_print_ratio("   D/C ", d, c);
    pqb_print_ratio("   A/D ", a, d);
    pqb_print_ratio("   A/E ", a, e);
    printf("\n");
    if (b > a) {
        pqb_print_ratio("  the naive substitution is ", b, a);
        printf(" SLOWER than software\n");
    }
    printf("  per-call acquire/release overhead ~%u cycles\n", (unsigned)(b - d));
}

/* --------------------------------- what mbedtls_sha256_init() alone gives us */

/*
 * SHRINCS started every context with mbedtls_sha256_init() and never called
 * mbedtls_sha256_starts().  init() only zeroes the context, and ctx->mode is
 * then the SHA_TYPE enum's zero value -- which is SHA1, not SHA2_256.  Show
 * what that actually computed, against the two candidate answers.
 */
static void pqb_mbedtls_mode_check(void)
{
    static const uint8_t abc[3] = { 'a', 'b', 'c' };
    /* FIPS 180-4 worked examples */
    static const uint8_t sha256_abc[32]
        = { 0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23,
              0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD };
    static const uint8_t sha1_abc[20] = { 0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25,
        0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D };
    mbedtls_sha256_context ctx;
    uint8_t out[32] = { 0 };

    printf("\n--- 2. what SHRINCS was actually hashing with\n");

    mbedtls_sha256_init(&ctx); /* no mbedtls_sha256_starts() -- as SHRINCS did */
    mbedtls_sha256_update(&ctx, abc, sizeof(abc));
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);

    pqb_print_hex("  mbedtls_sha256_init() only, \"abc\" -> ", out, 32);
    pqb_print_hex("  SHA-256(\"abc\")                      ", sha256_abc, 32);
    pqb_print_hex("  SHA-1(\"abc\")                        ", sha1_abc, 20);
    if (!memcmp(out, sha1_abc, sizeof(sha1_abc))) {
        printf("  => it was SHA-1, with 12 bytes of stale state appended\n");
    } else if (!memcmp(out, sha256_abc, sizeof(sha256_abc))) {
        printf("  => SHA-256 after all\n");
    } else {
        printf("  => neither\n");
    }

    /* And the replacement, for contrast. */
    sha2_256(out, abc, sizeof(abc));
    pqb_print_hex("  sha2_256(\"abc\")                      ", out, 32);
    printf("  => %s\n", memcmp(out, sha256_abc, 32) ? "WRONG" : "correct SHA-256");
}

/*
 * SHRINCS sign-and-verify under a key the scheme derives itself.
 *
 * The hard-coded key in sign_shrincs.c cannot be used for this: its pk.root
 * was generated while the SHA-1 defect was still present, so once the hashing
 * is corrected the recomputed root no longer matches it and verification
 * fails.  Deriving the key here separates "the scheme is broken" from "that
 * test vector is stale".
 */
static void pqb_shrincs_selftest(void)
{
    static const uint8_t msg[32] = { 0 };
    uint8_t seed64[64];
    PublicKey pk;
    SecretKey sk;
    State state;
    uint8_t* sig;
    size_t sig_len;
    int ok = 0;

    printf("\n--- 2b. SHRINCS sign/verify under a self-derived key\n");

    for (size_t i = 0; i < sizeof(seed64); ++i) {
        seed64[i] = (uint8_t)(i * 7u + 1u);
    }
    sig = malloc(N + WOTS_SIGN_LEN + 2 * N);
    if (!sig) {
        printf("  out of memory\n");
        return;
    }

    pq_hw_sha_mode = PQ_SHA_HW_HELD;
    pq_hw_sha_begin();
    shrincs_restore(seed64, &pk, &sk, &state, NULL);
    sig_len = N + WOTS_SIGN_LEN + (state.q + 1) * N;
    if (shrincs_sign_stateful(msg, sizeof(msg), &sk, &state, SWN, sig, pqb_noop_cb16, NULL, NULL)) {
        ok = shrincs_verify_stateful(msg, sizeof(msg), sig, (uint32_t)sig_len, &pk);
    }
    pq_hw_sha_end();

    printf("  q=%u, signature %u bytes, verifies: %s\n", (unsigned)state.q, (unsigned)sig_len,
        ok ? "yes" : "NO");
    free(sig);
}

/* ----------------------------------------------------- known-answer tests */

static slh_param_t pqb_prm_jade(void)
{
    slh_param_t prm;

    /* Jade's reduced parameter set, as used by the signing RPC when
     * is_standard is false.  No published vectors exist for it, so it is
     * checked by software/hardware equivalence instead. */
    memcpy(&prm, &slh_dsa_sha2_128s, sizeof(prm));
    prm.alg_id = "custom-slh-dsa";
    prm.h = 45;
    prm.d = 5;
    prm.hp = 9;
    prm.a = 13;
    prm.k = 10;
    prm.lg_w = 4;
    return prm;
}

static int pqb_kat_keygen(void)
{
    const size_t n = sizeof(slh_kat_keygen) / sizeof(slh_kat_keygen[0]);
    int pass = 0;

    for (size_t i = 0; i < n; ++i) {
        const slh_kat_keygen_t* v = &slh_kat_keygen[i];
        uint8_t sk[64] = { 0 };
        uint8_t pk[32] = { 0 };

        pq_hw_sha_begin();
        slh_keygen_internal(sk, pk, v->sk_seed, v->sk_prf, v->pk_seed, &slh_dsa_sha2_128s, NULL);
        pq_hw_sha_end();

        if (!memcmp(sk, v->sk, sizeof(sk)) && !memcmp(pk, v->pk, sizeof(pk))) {
            ++pass;
        } else {
            printf("    keyGen tc %d FAILED\n", v->tc_id);
            pqb_print_hex("      expected pk ", v->pk, 32);
            pqb_print_hex("      got      pk ", pk, 32);
        }
    }
    printf("    keyGen  %d/%u ACVP vectors pass\n", pass, (unsigned)n);
    return pass == (int)n;
}

static int pqb_kat_siggen(size_t limit)
{
    size_t n = sizeof(slh_kat_siggen) / sizeof(slh_kat_siggen[0]);
    int pass = 0;

    if (limit && limit < n) {
        n = limit;
    }
    for (size_t i = 0; i < n; ++i) {
        const slh_kat_siggen_t* v = &slh_kat_siggen[i];
        const size_t sig_sz = slh_sig_sz(&slh_dsa_sha2_128s);
        uint8_t* sig = malloc(sig_sz);
        size_t written;

        if (!sig) {
            printf("    sigGen tc %d SKIPPED (out of memory)\n", v->tc_id);
            continue;
        }
        memset(sig, 0, sig_sz);

        pq_hw_sha_begin();
        if (v->external) {
            written = slh_sign(sig, v->msg, v->msg_len, v->ctx, v->ctx_len, v->sk, NULL,
                &slh_dsa_sha2_128s, NULL, NULL, NULL);
        } else {
            written = slh_sign_internal(sig, v->msg, v->msg_len, v->sk, NULL, &slh_dsa_sha2_128s);
        }
        pq_hw_sha_end();

        if (written == v->expected_len && !memcmp(sig, v->expected, v->expected_len)) {
            ++pass;
        } else {
            printf("    sigGen tc %d FAILED (wrote %u, expected %u)\n", v->tc_id, (unsigned)written,
                (unsigned)v->expected_len);
            pqb_print_hex("      expected[0:32] ", v->expected, 32);
            pqb_print_hex("      got     [0:32] ", sig, 32);
        }
        free(sig);
    }
    printf("    sigGen  %d/%u ACVP vectors pass\n", pass, (unsigned)n);
    return pass == (int)n;
}

/* --------------------------------------------------------------- timings */

static uint32_t pqb_progress_yields = 0;

/* Timestamps of each progress callback, so the intervals during which SHA and
 * AES are unavailable to the rest of the device can be reported. */
#define BENCH_MAX_GAPS 16
static int64_t pqb_gap_at[BENCH_MAX_GAPS];
static int pqb_gap_n = 0;

static void pqb_progress_cb(uint16_t current, void* userdata)
{
    (void)current;
    (void)userdata;
    ++pqb_progress_yields;
    if (pqb_gap_n < BENCH_MAX_GAPS) {
        pqb_gap_at[pqb_gap_n++] = esp_timer_get_time();
    }
    /* Nothing to do here: slh_dsa.c already suspends the hold around this
     * callback and resumes after it, so the peripheral is free for the whole
     * time the callback runs.  Assert that, since a callback that ran with the
     * hold still taken would deadlock the moment it tried to hash. */
    if (pq_hw_sha_held_and_active()) {
        printf("    WARNING: progress callback entered with the SHA hold still taken\n");
    }
}

static int64_t pqb_last_t0 = 0, pqb_last_t1 = 0;

/* Times one operation, reporting wall time and cycles per compression.
 * Returns the elapsed milliseconds. */
static uint32_t pqb_one(const char* label, void (*run)(const slh_param_t*, void*),
    const slh_param_t* prm, void* out)
{
    int64_t t0, t1;
    uint32_t compressions, ms;

    pq_sha256_compress_count = 0;
    pqb_progress_yields = 0;
    pqb_gap_n = 0;
    pq_hw_sha_worst_hold_us = 0;
    pq_hw_sha_yield_count = 0;

    t0 = esp_timer_get_time();
    pq_hw_sha_begin();
    run(prm, out);
    pq_hw_sha_end();
    t1 = esp_timer_get_time();

    compressions = pq_sha256_compress_count;
    ms = (uint32_t)((t1 - t0) / 1000);

    printf("    %-22s %6u ms   %8u compressions   %5u cycles/compression",
        label, (unsigned)ms, (unsigned)compressions,
        (unsigned)(compressions ? ((uint64_t)ms * 1000u * CPU_MHZ) / compressions : 0));
    if (pqb_progress_yields) {
        printf("   %u layers", (unsigned)pqb_progress_yields);
    }
    printf("\n");
    if (pq_hw_sha_worst_hold_us) {
        printf("      SHA/AES locked out at most %u ms in one stretch, %u hand-backs\n",
            (unsigned)(pq_hw_sha_worst_hold_us / 1000u),
            (unsigned)pq_hw_sha_yield_count);
    }

    pqb_last_t0 = t0;
    pqb_last_t1 = t1;
    return ms;
}

/* How long the rest of the device goes without access to SHA and AES: the
 * stretch before the first progress callback, the stretches between callbacks,
 * and the tail after the last one. */
static void pqb_report_gaps(void)
{
    uint32_t worst = 0;
    int64_t prev = pqb_last_t0;

    if (pqb_gap_n <= 0) {
        return;
    }
    printf("    SHA/AES unavailable for   ");
    for (int i = 0; i < pqb_gap_n; ++i) {
        const uint32_t ms = (uint32_t)((pqb_gap_at[i] - prev) / 1000);
        printf("%u ", (unsigned)ms);
        if (ms > worst) {
            worst = ms;
        }
        prev = pqb_gap_at[i];
    }
    {
        const uint32_t tail = (uint32_t)((pqb_last_t1 - prev) / 1000);
        printf("%u ms in turn", (unsigned)tail);
        if (tail > worst) {
            worst = tail;
        }
    }
    printf("  (worst %u ms)\n", (unsigned)worst);
}

typedef struct {
    uint8_t sk[64];
    uint8_t pk[32];
} pqb_keys_t;

static void pqb_run_keygen(const slh_param_t* prm, void* out)
{
    pqb_keys_t* k = (pqb_keys_t*)out;
    const slh_kat_keygen_t* v = &slh_kat_keygen[0];

    slh_keygen_internal(k->sk, k->pk, v->sk_seed, v->sk_prf, v->pk_seed, prm, NULL);
}

static const uint8_t* pqb_sig_sk = NULL;

static void pqb_run_siggen(const slh_param_t* prm, void* out)
{
    const slh_kat_siggen_t* v = &slh_kat_siggen[0];

    slh_sign((uint8_t*)out, v->msg, v->msg_len, v->ctx, v->ctx_len, pqb_sig_sk, NULL, prm,
        pqb_progress_cb, NULL, NULL);
}

/* Times KeyGen and SigGen in the currently selected configuration, and returns
 * the signature so the two configurations can be compared byte for byte. */
static void pqb_timings(const slh_param_t* prm, const char* set_name, uint8_t* sig_out, int reps)
{
    pqb_keys_t keys;
    uint32_t lo = 0xFFFFFFFFu, hi = 0, sum = 0;

    printf("  %s (h=%u d=%u hp=%u a=%u k=%u, sig %u bytes)\n", set_name, (unsigned)prm->h,
        (unsigned)prm->d, (unsigned)prm->hp, (unsigned)prm->a, (unsigned)prm->k,
        (unsigned)slh_sig_sz(prm));

    pqb_one("KeyGen", pqb_run_keygen, prm, &keys);

    /* Sign under the key the KAT vector uses, so the standard-parameter run is
     * the same computation the known-answer test just validated. */
    pqb_sig_sk = slh_kat_siggen[0].sk;
    for (int i = 0; i < reps; ++i) {
        const uint32_t ms = pqb_one("SigGen", pqb_run_siggen, prm, sig_out);

        if (ms < lo) {
            lo = ms;
        }
        if (ms > hi) {
            hi = ms;
        }
        sum += ms;
        if (i == 0) {
            pqb_report_gaps();
        }
    }
    if (reps > 1) {
        printf("    SigGen over %d runs        min %u ms  mean %u ms  max %u ms  spread %u ms\n",
            reps, (unsigned)lo, (unsigned)(sum / (uint32_t)reps), (unsigned)hi,
            (unsigned)(hi - lo));
    }
}

/* ------------------------------------------------- SHRINCS and XMSS timing */

/*
 * Both schemes call their progress callback without checking it for NULL
 * (shrincs/wots_c.c and xmss/xmss_core.c), so pass a no-op rather than NULL.
 * That also matches the RPC path, which always supplies one.
 */
static void pqb_noop_cb16(uint16_t value, void* ud)
{
    (void)value;
    (void)ud;
}

static void pqb_noop_cb32(uint32_t current, uint32_t total, void* ud)
{
    (void)current;
    (void)total;
    (void)ud;
}

/* Mirrors shrincs_key_gen_process(): build the pk_seed-prefixed context, then
 * walk the stateful tree. */
static uint32_t pqb_shrincs_keygen(const uint8_t* seed64)
{
    uint8_t adrs[32] = { 0 };
    uint8_t pk_sf[N];
    SHA256_CTX hash_ctx;
    int64_t t0, t1;

    pq_sha256_compress_count = 0;
    pq_hw_sha_worst_hold_us = 0;

    t0 = esp_timer_get_time();
    pq_hw_sha_begin();
    sha256_init_ctx(&hash_ctx);
    sha256_add_to_ctx(&hash_ctx, seed64 + 2 * N, N);
    sha256_add_to_ctx(&hash_ctx, adrs, 32);
    sha256_add_to_ctx(&hash_ctx, adrs, 16);
    uxmss_root(seed64, &hash_ctx, adrs, pk_sf, NULL);
    pq_hw_sha_end();
    t1 = esp_timer_get_time();

    return (uint32_t)((t1 - t0) / 1000);
}

/* Mirrors sign_shrincs_process() with the same hard-coded key it uses. */
static uint32_t pqb_shrincs_sign(uint8_t* sig_out, size_t* sig_len_out, PublicKey* pk_out)
{
    static const uint8_t sk_bytes[96]
        = { 0x05, 0x17, 0x40, 0x0A, 0x7D, 0x4F, 0x5A, 0x53, 0x2D, 0x4F, 0x34, 0xB0, 0x77, 0x18, 0x2C, 0xAF,
              0x1A, 0x79, 0xE4, 0x06, 0x40, 0x4E, 0x29, 0xA7, 0xFE, 0xED, 0x94, 0xAA, 0x54, 0x63, 0x30, 0xAC,
              0x00, 0xAE, 0x2C, 0x28, 0x2F, 0x33, 0xB3, 0x19, 0xD8, 0x3B, 0x70, 0x5B, 0x4B, 0x54, 0x87, 0xC6,
              0x18, 0x31, 0x1F, 0x77, 0xA5, 0x28, 0x3C, 0xF3, 0x9A, 0xAB, 0xAF, 0x35, 0xDC, 0x3D, 0xFD, 0x79,
              0x91, 0x8F, 0xD1, 0x7D, 0x88, 0x9F, 0x34, 0xEB, 0x76, 0xA9, 0x9A, 0x0C, 0x93, 0xA2, 0x01, 0x5E,
              0xDA, 0x5A, 0x08, 0xDC, 0x47, 0xD1, 0xE0, 0x5D, 0x0D, 0x4D, 0x81, 0x6F, 0x72, 0xE7, 0x8E, 0x27 };
    const uint8_t msg[32] = { 0 };
    SecretKey sk;
    State state = { .q = 0, .valid = 1 };
    int64_t t0, t1;

    memcpy(sk.seed, sk_bytes, N);
    memcpy(sk.prf, sk_bytes + N, N);
    memcpy(sk.sf, sk_bytes + N * 2, N);
    memcpy(sk.sl, sk_bytes + N * 3, N);
    memcpy(sk.pk.seed, sk_bytes + N * 4, N);
    memcpy(sk.pk.root, sk_bytes + N * 5, N);

    *sig_len_out = N + WOTS_SIGN_LEN + (state.q + 1) * N;
    if (pk_out) {
        *pk_out = sk.pk;
    }

    pq_sha256_compress_count = 0;
    pq_hw_sha_worst_hold_us = 0;

    t0 = esp_timer_get_time();
    pq_hw_sha_begin();
    shrincs_sign_stateful(msg, sizeof(msg), &sk, &state, SWN, sig_out, pqb_noop_cb16, NULL, NULL);
    pq_hw_sha_end();
    t1 = esp_timer_get_time();

    return (uint32_t)((t1 - t0) / 1000);
}

/* XMSS as Jade configures it: OID 0x000000ff, SHA-2, n = 16. */
#define PQB_XMSS_OID 0x000000ff

static uint32_t pqb_xmss_keygen(xmss_params* xp, uint8_t* sk, uint8_t* pk, const uint8_t* seed64)
{
    int64_t t0, t1;

    pq_sha256_compress_count = 0;
    pq_hw_sha_worst_hold_us = 0;

    t0 = esp_timer_get_time();
    pq_hw_sha_begin();
    xmssmt_core_seed_keypair(xp, pk, sk, seed64, pqb_noop_cb32, NULL);
    pq_hw_sha_end();
    t1 = esp_timer_get_time();

    return (uint32_t)((t1 - t0) / 1000);
}

static uint32_t pqb_xmss_sign(xmss_params* xp, uint8_t* sk, uint8_t* sm, unsigned long long* smlen)
{
    const uint8_t msg[32] = { 0 };
    int64_t t0, t1;

    pq_sha256_compress_count = 0;
    pq_hw_sha_worst_hold_us = 0;

    t0 = esp_timer_get_time();
    pq_hw_sha_begin();
    xmss_core_sign(xp, sk, sm, smlen, msg, sizeof(msg), pqb_noop_cb32, NULL);
    pq_hw_sha_end();
    t1 = esp_timer_get_time();

    return (uint32_t)((t1 - t0) / 1000);
}

static void pqb_print_op(const char* label, uint32_t ms)
{
    const uint32_t n = pq_sha256_compress_count;

    printf("    %-24s %6u ms   %8u compressions   %5u cycles/compression", label, (unsigned)ms,
        (unsigned)n, (unsigned)(n ? ((uint64_t)ms * 1000u * CPU_MHZ) / n : 0));
    if (pq_hw_sha_worst_hold_us) {
        printf("   lockout %u ms", (unsigned)(pq_hw_sha_worst_hold_us / 1000u));
    }
    printf("\n");
}

/* Times SHRINCS and XMSS in both configurations.  Both hash through the same
 * sha2_256_compress() as SLH-DSA now, so the runtime switch covers them too. */
static void pqb_shrincs_and_xmss(void)
{
    uint8_t seed64[64];
    uint8_t* sig = NULL;
    size_t sig_len = 0;
    xmss_params xp;
    uint8_t *xsk = NULL, *xpk = NULL, *xsm = NULL;
    unsigned long long smlen = 0;
    uint32_t ms;

    printf("\n--- 5. SHRINCS and XMSS\n");

    for (size_t i = 0; i < sizeof(seed64); ++i) {
        seed64[i] = (uint8_t)(i * 7u + 1u);
    }

    /* ---- SHRINCS-B ---- */
    sig = malloc(N + WOTS_SIGN_LEN + 2 * N);
    if (!sig) {
        printf("  out of memory for the SHRINCS signature\n");
        return;
    }
    printf("\n  SHRINCS-B (N=%u, HSF=%u, swn=%u)\n", (unsigned)N, (unsigned)HSF, (unsigned)SWN);

    {
        static const struct {
            pq_sha_mode_t mode;
            const char* name;
        } arms[] = {
            { PQ_SHA_SW, "software" },
            { PQ_SHA_HW_PERCALL, "hardware, acquired per hash (what mbedtls_sha256_* did)" },
            { PQ_SHA_HW_HELD, "hardware, held" },
        };
        uint8_t* first = malloc(N + WOTS_SIGN_LEN + 2 * N);
        PublicKey pk;
        int same = 1, verified = 0;

        for (size_t a = 0; a < 3; ++a) {
            pq_hw_sha_mode = arms[a].mode;
            printf("   %s\n", arms[a].name);
            ms = pqb_shrincs_keygen(seed64);
            pqb_print_op("KeyGen", ms);
            ms = pqb_shrincs_sign(sig, &sig_len, &pk);
            pqb_print_op("SigGen", ms);
            if (!first) {
                continue;
            }
            if (a == 0) {
                memcpy(first, sig, sig_len);
            } else if (memcmp(first, sig, sig_len) != 0) {
                same = 0;
            }
        }
        pq_hw_sha_mode = PQ_SHA_HW_HELD;
        pq_hw_sha_begin();
        verified = shrincs_verify_stateful((const uint8_t*)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
                                           "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            32, sig, (uint32_t)sig_len, &pk);
        pq_hw_sha_end();
        printf("    signature %u bytes; all three regimes agree: %s; verifies: %s\n",
            (unsigned)sig_len, first ? (same ? "yes" : "NO") : "?", verified ? "yes" : "NO");
        free(first);
    }
    free(sig);

    /* ---- XMSS ---- */
    if (xmss_parse_oid(&xp, PQB_XMSS_OID) != 0) {
        printf("\n  XMSS: bad OID\n");
        return;
    }
    xsk = malloc(xp.sk_bytes);
    xpk = malloc(xp.pk_bytes);
    xsm = malloc((size_t)xp.sig_bytes + 32);
    if (!xsk || !xpk || !xsm) {
        printf("\n  out of memory for XMSS\n");
        free(xsk);
        free(xpk);
        free(xsm);
        return;
    }
    printf("\n  XMSS (oid 0x%08x, n=%u, sig %u bytes)\n", (unsigned)PQB_XMSS_OID, (unsigned)xp.n,
        (unsigned)xp.sig_bytes);

    {
        static const struct {
            pq_sha_mode_t mode;
            const char* name;
        } arms[] = {
            { PQ_SHA_SW, "software" },
            { PQ_SHA_HW_PERCALL, "hardware, acquired per hash (what mbedtls_sha256_* did)" },
            { PQ_SHA_HW_HELD, "hardware, held" },
        };
        uint8_t* first = malloc((size_t)xp.sig_bytes + 32);
        uint8_t* opened = malloc((size_t)xp.sig_bytes + 32);
        unsigned long long olen = 0;
        int same = 1, verified = 0;

        for (size_t a = 0; a < 3; ++a) {
            pq_hw_sha_mode = arms[a].mode;
            printf("   %s\n", arms[a].name);
            /* keygen resets the signing index, so every arm signs index 0 */
            ms = pqb_xmss_keygen(&xp, xsk, xpk, seed64);
            pqb_print_op("KeyGen", ms);
            ms = pqb_xmss_sign(&xp, xsk, xsm, &smlen);
            pqb_print_op("SigGen", ms);
            if (!first) {
                continue;
            }
            if (a == 0) {
                memcpy(first, xsm, (size_t)smlen);
            } else if (memcmp(first, xsm, (size_t)smlen) != 0) {
                same = 0;
            }
        }
        pq_hw_sha_mode = PQ_SHA_HW_HELD;
        if (opened) {
            pq_hw_sha_begin();
            verified = (xmss_core_sign_open(&xp, opened, &olen, xsm, smlen, xpk) == 0);
            pq_hw_sha_end();
        }
        printf("    signature %u bytes; all three regimes agree: %s; verifies: %s\n",
            (unsigned)smlen, first ? (same ? "yes" : "NO") : "?", verified ? "yes" : "NO");
        free(first);
        free(opened);
    }

    free(xsk);
    free(xpk);
    free(xsm);
}

/* ------------------------------------------------------------------ entry */

void pq_bench_run(void)
{
    const slh_param_t prm_std = slh_dsa_sha2_128s;
    const slh_param_t prm_jade = pqb_prm_jade();
    uint8_t* sig_sw = NULL;
    uint8_t* sig_hw = NULL;
    const size_t sig_std = slh_sig_sz(&prm_std);
    const size_t sig_jade = slh_sig_sz(&prm_jade);
    const size_t sig_max = sig_std > sig_jade ? sig_std : sig_jade;
    uint32_t t0, t1, yield_cycles;
    int kat_sw, kat_hw;

    /* The console is the chip's own USB serial/JTAG, which re-enumerates on
     * reset; give the host a moment to reattach before the first line. */
    vTaskDelay(pdMS_TO_TICKS(3000));

    printf("\n");
    printf("========================================================================\n");
    printf(" Post-quantum signatures on the ESP32-S3 SHA accelerator\n");
    printf(" CPU %u MHz, %u probe iterations\n", (unsigned)CPU_MHZ, (unsigned)PROBE_ITERS);
    printf("========================================================================\n");

    pqb_probe();
    pqb_mbedtls_mode_check();
    pqb_shrincs_selftest();

    /* --- 3. known-answer tests, both configurations --- */
    printf("\n--- 3. NIST ACVP known-answer tests, SLH-DSA-SHA2-128s\n");

    printf("  software configuration:\n");
    pq_hw_sha_mode = PQ_SHA_SW;
    kat_sw = pqb_kat_keygen();
    kat_sw &= pqb_kat_siggen(1); /* one signature; software costs ~49 s each */

    printf("  hardware configuration:\n");
    pq_hw_sha_mode = PQ_SHA_HW_HELD;
    kat_hw = pqb_kat_keygen();
    kat_hw &= pqb_kat_siggen(0); /* all vectors */

    printf("  => software %s, hardware %s\n", kat_sw ? "PASS" : "FAIL", kat_hw ? "PASS" : "FAIL");
    if (!(kat_sw && kat_hw)) {
        printf("  known-answer tests failed; not reporting timings\n");
        return;
    }

    /* --- 3. timings, both configurations --- */
    sig_sw = malloc(sig_max);
    sig_hw = malloc(sig_max);
    if (!sig_sw || !sig_hw) {
        printf("\n  out of memory for signature buffers\n");
        free(sig_sw);
        free(sig_hw);
        return;
    }

    printf("\n--- 4. SLH-DSA KeyGen and SigGen\n");

    printf("\n  === software ===\n");
    pq_hw_sha_mode = PQ_SHA_SW;
    pqb_timings(&prm_std, "SLH-DSA-SHA2-128s", sig_sw, 1);

    printf("\n  === hardware, held ===\n");
    pq_hw_sha_mode = PQ_SHA_HW_HELD;
    pqb_timings(&prm_std, "SLH-DSA-SHA2-128s", sig_hw, 1);

    printf("\n  signatures agree byte for byte: %s\n",
        memcmp(sig_sw, sig_hw, sig_std) == 0 ? "yes" : "NO");

    printf("\n  === Jade's reduced parameter set ===\n");
    pq_hw_sha_mode = PQ_SHA_SW;
    pqb_timings(&prm_jade, "custom-slh-dsa", sig_sw, 1);
    pq_hw_sha_mode = PQ_SHA_HW_HELD;
    pqb_timings(&prm_jade, "custom-slh-dsa", sig_hw, 1);
    printf("\n  signatures agree byte for byte: %s\n",
        memcmp(sig_sw, sig_hw, sig_jade) == 0 ? "yes" : "NO");

    free(sig_sw);
    free(sig_hw);

    pqb_shrincs_and_xmss();

    /* --- 6. cost of the progress-callback yield --- */
    printf("\n--- 6. suspend + resume (what one progress callback costs)\n");
    pq_hw_sha_mode = PQ_SHA_HW_HELD;
    pq_hw_sha_begin();
    for (int i = 0; i < 16; ++i) {
        pq_hw_sha_yield();
    }
    t0 = esp_cpu_get_cycle_count();
    for (int i = 0; i < 256; ++i) {
        pq_hw_sha_yield();
    }
    t1 = esp_cpu_get_cycle_count();
    pq_hw_sha_end();
    yield_cycles = (t1 - t0) / 256;
    printf("  %u cycles per yield (%u us)\n", (unsigned)yield_cycles,
        (unsigned)(yield_cycles / CPU_MHZ));

    printf("\n========================================================================\n\n");
    fflush(stdout);
}

#endif /* CONFIG_JADE_PQ_BENCH */
#endif // AMALGAMATED_BUILD

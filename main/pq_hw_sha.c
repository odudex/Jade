/*
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Jade-specific: SLH-DSA SHA-256 compression on the ESP32 SHA accelerator.
 * See pq_hw_sha.h for why the peripheral is held rather than acquired
 * per hash.
 */

#ifndef AMALGAMATED_BUILD
#include "pq_hw_sha.h"

#ifdef CONFIG_JADE_PQ_HW_SHA

#include <esp_timer.h>
#include <hal/sha_types.h>
#include <sha/sha_core.h>
#include <soc/soc_caps.h>

#if !SOC_SHA_SUPPORT_RESUME
#error "SLH-DSA hardware SHA-256 needs a SHA engine that can resume from an arbitrary midstate"
#endif

/* Nesting depth of pq_hw_sha_begin()/end() pairs. */
static int s_hold_depth = 0;
/* Set while the hold is temporarily handed back by pq_hw_sha_suspend(). */
static bool s_suspended = false;

#ifdef CONFIG_JADE_PQ_BENCH
pq_sha_mode_t pq_hw_sha_mode = PQ_SHA_HW_HELD;
uint32_t pq_hw_sha_worst_hold_us = 0;
static int64_t s_held_since = 0;

/* Called whenever the peripheral is actually taken. */
static void bench_hold_started(void) { s_held_since = esp_timer_get_time(); }

/* Called whenever it is actually given back. */
static void bench_hold_ended(void)
{
    const int64_t us = esp_timer_get_time() - s_held_since;
    if (us > 0 && (uint32_t)us > pq_hw_sha_worst_hold_us) {
        pq_hw_sha_worst_hold_us = (uint32_t)us;
    }
}

/* Only change pq_hw_sha_mode outside a begin()/end() bracket, so that the hold
 * depth stays balanced. */
#define PQ_HW_BENCH_DISABLED() (pq_hw_sha_mode != PQ_SHA_HW_HELD)
#else
#define bench_hold_started() ((void)0)
#define bench_hold_ended() ((void)0)
#define PQ_HW_BENCH_DISABLED() (false)
#endif

void pq_hw_sha_begin(void)
{
    if (PQ_HW_BENCH_DISABLED()) {
        return;
    }
    if (s_hold_depth++ == 0) {
        esp_sha_acquire_hardware();
        esp_sha_set_mode(SHA2_256);
        bench_hold_started();
    }
}

void pq_hw_sha_end(void)
{
    if (PQ_HW_BENCH_DISABLED()) {
        return;
    }
    if (s_hold_depth > 0 && --s_hold_depth == 0) {
        if (!s_suspended) {
            esp_sha_release_hardware();
            bench_hold_ended();
        }
        s_suspended = false;
    }
}

void pq_hw_sha_suspend(void)
{
    if (s_hold_depth > 0 && !s_suspended) {
        esp_sha_release_hardware();
        bench_hold_ended();
        s_suspended = true;
    }
}

void pq_hw_sha_resume(void)
{
    if (s_hold_depth > 0 && s_suspended) {
        esp_sha_acquire_hardware();
        esp_sha_set_mode(SHA2_256);
        bench_hold_started();
        s_suspended = false;
    }
}

void pq_hw_sha_yield(void)
{
    pq_hw_sha_suspend();
    pq_hw_sha_resume();
}

bool pq_hw_sha_held(void) { return s_hold_depth > 0; }

bool pq_hw_sha_held_and_active(void) { return s_hold_depth > 0 && !s_suspended; }

/*
 * slhdsa-c keeps its SHA-256 context as
 *
 *     struct { uint32_t s[8 + 24]; size_t i, len; }
 *
 * with the chaining state in s[0..7] and the 64-byte message block in
 * s[8..23], both already in big-endian byte order -- which is exactly the
 * SHA_H_BASE + SHA_TEXT_BASE register layout.  Neither sha_ll_write_digest()
 * nor sha_ll_fill_text_block() byteswaps, so the context maps onto the
 * peripheral with no marshalling at all, and the 24 rev8_be32() calls the
 * software compression performs disappear along with it.
 *
 * The mode is set once, in pq_hw_sha_begin(); all this does per hash is
 * move 32 words in and 8 words out.
 */
void sha2_256_compress_hw(void* v)
{
    uint32_t* sp = (uint32_t*)v;

    esp_sha_write_digest_state(SHA2_256, sp); /* midstate -> SHA_H_BASE */
    esp_sha_block(SHA2_256, sp + 8, false); /* block -> SHA_TEXT_BASE, then CONTINUE */
    esp_sha_read_digest_state(SHA2_256, sp); /* wait idle, SHA_H_BASE -> state */
}

#endif /* CONFIG_JADE_PQ_HW_SHA */

/*
 * The single symbol every sha2_256_update()/sha2_256_final_len() call in
 * slh_dsa/ routes through, so replacing it here covers 100% of the SLH-DSA
 * compressions with no further changes to the vendored code.
 */
#ifdef CONFIG_JADE_PQ_BENCH
/* Exact compression count for the benchmark, so cost per operation can be
 * divided out into cost per compression.  Costs a couple of cycles per hash and
 * is not built into production images. */
uint32_t pq_sha256_compress_count = 0;
#endif

void sha2_256_compress(void* v)
{
#ifdef CONFIG_JADE_PQ_BENCH
    ++pq_sha256_compress_count;
    if (pq_hw_sha_mode == PQ_SHA_HW_PERCALL) {
        /* The old behaviour, reproduced for comparison: take the crypto lock,
         * enable the bus clock and reset the peripheral, for one compression. */
        esp_sha_acquire_hardware();
        esp_sha_set_mode(SHA2_256);
        sha2_256_compress_hw(v);
        esp_sha_release_hardware();
        return;
    }
#endif
#ifdef CONFIG_JADE_PQ_HW_SHA
    /* The hardware path is only valid while the peripheral is actually taken.
     * Driving an unclocked SHA engine does not fail quietly: the digest reads
     * back as all zeroes and ESP-IDF's fault-injection check calls abort().
     * Guarding here keeps correctness independent of the bracketing -- a missed
     * pq_hw_sha_begin() costs speed, never a wrong answer or a panic -- for
     * one predictable branch against roughly a thousand cycles of work. */
    if (s_hold_depth > 0 && !s_suspended) {
        sha2_256_compress_hw(v);
        return;
    }
#endif
    sha2_256_compress_sw(v);
}
#endif // AMALGAMATED_BUILD

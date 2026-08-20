/*
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Jade-specific: route the SLH-DSA SHA-256 compression function onto the
 * ESP32 SHA accelerator.
 *
 * The accelerator only pays for itself if the peripheral is *held* across a
 * whole SLH-DSA operation.  Acquiring it per hash costs a crypto-lock take, a
 * bus-clock enable and a peripheral reset, which together exceed the cost of
 * the software compression being replaced -- the naive substitution is slower
 * than not using the hardware at all.
 *
 * So every entry point into the SLH-DSA code must be bracketed:
 *
 *     pq_hw_sha_begin();
 *     ... slh_sign(...) ...
 *     pq_hw_sha_end();
 *
 * While the hardware is held, nothing else on the device may use SHA or AES.
 * pq_hw_sha_yield() releases and reacquires it, and is called from the
 * per-layer progress callback so the rest of the system is not starved for the
 * whole of a multi-second signature.
 */

#ifndef _PQ_HW_SHA_H_
#define _PQ_HW_SHA_H_

#include <sdkconfig.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Portable C compression from sha2_256.c.  Always built, so the hardware and
 * software paths stay comparable (and so the benchmark can price both). */
void sha2_256_compress_sw(void* v);

#ifdef CONFIG_JADE_PQ_HW_SHA

/* Acquire/release the SHA peripheral around an SLH-DSA operation.  Nestable:
 * only the outermost begin/end pair touches the hardware. */
void pq_hw_sha_begin(void);
void pq_hw_sha_end(void);

/* Temporarily hand the peripheral back while still inside a begin()/end()
 * bracket, so that other tasks -- and any code the progress callback reaches,
 * which on a wallet may well hash -- are not locked out of SHA and AES for the
 * whole of a multi-second signature.  Safe because no SLH-DSA state lives in
 * the peripheral between compressions: sha2_256_compress_hw() writes the full
 * midstate on every call.  Both are no-ops if the hardware is not held. */
void pq_hw_sha_suspend(void);
void pq_hw_sha_resume(void);

/* suspend() immediately followed by resume(). */
void pq_hw_sha_yield(void);

/* True between begin() and the matching end(). */
bool pq_hw_sha_held(void);

/* True only when the peripheral is actually taken right now, i.e. held and not
 * currently suspended. */
bool pq_hw_sha_held_and_active(void);

/* One compression on the held peripheral.  Undefined behaviour unless called
 * between pq_hw_sha_begin() and pq_hw_sha_end(). */
void sha2_256_compress_hw(void* v);

#ifdef CONFIG_JADE_PQ_BENCH
/* Number of sha2_256_compress() calls since boot.  Benchmark builds only. */
extern uint32_t pq_sha256_compress_count;

/* The three ways this codebase has driven SHA-256, so all three can be timed
 * from a single image. */
typedef enum {
    PQ_SHA_SW = 0, /* portable C -- the reference implementation           */
    PQ_SHA_HW_PERCALL, /* accelerator, acquired and released per hash -- what
                        * mbedtls_sha256_* does, and therefore what SHRINCS and
                        * XMSS used before this change                     */
    PQ_SHA_HW_HELD, /* accelerator, held across the whole operation        */
} pq_sha_mode_t;

extern pq_sha_mode_t pq_hw_sha_mode;



/* Longest single stretch, in microseconds, for which the peripheral was
 * actually taken -- i.e. how long the rest of the device went without SHA and
 * AES.  Reset it before an operation and read it after. */
extern uint32_t pq_hw_sha_worst_hold_us;

/* Number of periodic hand-backs performed. */
extern uint32_t pq_hw_sha_yield_count;
#endif

#else /* !CONFIG_JADE_PQ_HW_SHA */

#define pq_hw_sha_begin() ((void)0)
#define pq_hw_sha_end() ((void)0)
#define pq_hw_sha_suspend() ((void)0)
#define pq_hw_sha_resume() ((void)0)
#define pq_hw_sha_yield() ((void)0)
#define pq_hw_sha_held() (false)
#define pq_hw_sha_held_and_active() (false)

#endif /* CONFIG_JADE_PQ_HW_SHA */

#ifdef __cplusplus
}
#endif

/* _PQ_HW_SHA_H_ */
#endif

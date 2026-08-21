/*
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 *
 * Jade-specific: boot-time SLH-DSA hash benchmark and known-answer tests.
 * Development builds only -- enabled by CONFIG_JADE_PQ_BENCH.
 */

#ifndef _PQ_BENCH_H_
#define _PQ_BENCH_H_

#include <sdkconfig.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_JADE_PQ_BENCH
/* Prints the per-compression cost table, runs the NIST ACVP known-answer tests
 * in both the software and the hardware configuration, and times KeyGen and
 * SigGen both ways.  Blocking; takes a few minutes. */
void pq_bench_run(void);
#else
#define pq_bench_run() ((void)0)
#endif

#ifdef __cplusplus
}
#endif

/* _PQ_BENCH_H_ */
#endif

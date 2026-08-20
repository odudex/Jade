#ifndef HASH_H
#define HASH_H

#include <string.h>

/*
 * Jade: SHRINCS hashes through the same SHA-256 implementation as SLH-DSA, so
 * that all of it goes via sha2_256_compress() and picks up the held hardware
 * accelerator (see pq_hw_sha.h).  Previously this was mbedtls_sha256_*, which
 * on this IDF is hardware-backed but acquires and releases the peripheral on
 * every update and finish -- overhead that dominates hashes this short.
 *
 * Note this also fixes a correctness bug.  Contexts here are started without
 * ever calling mbedtls_sha256_starts(), and mbedtls_sha256_init() only zeroes
 * the context -- leaving ctx->mode at the enum's zero value, which is SHA1.
 * The peripheral was therefore asked for SHA-1, and the top 12 bytes of every
 * "SHA-256" result were whatever the state happened to hold.
 */
#include "../slh_dsa/sha2_api.h"

typedef sha2_256_t SHA256_CTX;

/* Start a fresh SHA-256 context. */
static inline void sha256_init_ctx(SHA256_CTX* ctx) { sha2_256_init(ctx); }

/* Duplicate a context, so a common prefix can be hashed once and reused. */
static inline void sha256_copy_ctx(SHA256_CTX* dst, const SHA256_CTX* src) { sha2_256_copy(dst, src); }

/* Contexts hold no resources; kept so the call sites read the same. */
static inline void sha256_free_ctx(SHA256_CTX* ctx) { (void)ctx; }

#include "constants.h"
#include "address.h"

void sha256_add_to_ctx(SHA256_CTX* base_ctx, const uint8_t* data, uint32_t len);

void sha256_finalize(SHA256_CTX* base_ctx, uint8_t* out);

void sha256_finalize_32(SHA256_CTX* base_ctx, uint8_t* out);

void prf_msg(const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* opt_rand, const uint8_t* message, uint32_t message_len, uint32_t is_ctr, uint32_t ctr, uint32_t mask_len, uint8_t* out);

#endif

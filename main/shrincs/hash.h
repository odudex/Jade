#ifndef HASH_H
#define HASH_H

#include <string.h>

#include <mbedtls/sha256.h>
typedef mbedtls_sha256_context SHA256_CTX;

#include "constants.h"
#include "address.h"

static inline void sha_init(SHA256_CTX* ctx);

void sha256_add_to_ctx(SHA256_CTX* base_ctx, const uint8_t* data, uint32_t len);

void sha256_finalize(SHA256_CTX* base_ctx, uint8_t* out);

void sha256_finalize_32(SHA256_CTX* base_ctx, uint8_t* out);

void prf_msg(const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* opt_rand, const uint8_t* message, uint32_t message_len, uint32_t is_ctr, uint32_t ctr, uint32_t mask_len, uint8_t* out);

#endif
#include "hash.h"

static inline void sha_init(SHA256_CTX* ctx) {
    mbedtls_sha256_init(ctx);
    mbedtls_sha256_starts(ctx, 0);
}

void sha256_add_to_ctx(SHA256_CTX* base_ctx, const uint8_t* data, uint32_t len) {
    mbedtls_sha256_update(base_ctx, data, len);
}

void sha256_finalize(SHA256_CTX* base_ctx, uint8_t* out) {
    uint8_t full_hash[32];
    mbedtls_sha256_finish(base_ctx, full_hash);
    mbedtls_sha256_free(base_ctx);
    memcpy(out, full_hash, N);
}

void sha256_finalize_32(SHA256_CTX* base_ctx, uint8_t* out) {
    uint8_t full_hash[32];
    mbedtls_sha256_finish(base_ctx, full_hash);
    mbedtls_sha256_free(base_ctx);
    memcpy(out, full_hash, 32);
}

static inline uint32_t min_u32(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}

void prf_msg(const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* opt_rand, const uint8_t* message, uint32_t message_len, uint32_t is_ctr, uint32_t ctr, uint32_t mask_len, uint8_t* out)
{
    SHA256_CTX ctx;
    sha_init(&ctx);  

    sha256_add_to_ctx(&ctx, sk_prf, N);
    sha256_add_to_ctx(&ctx, pk_seed, N);
    sha256_add_to_ctx(&ctx, opt_rand, N);
    if (is_ctr)
    {
        sha256_add_to_ctx(&ctx, (const uint8_t*)&ctr, 4);
    }
    sha256_add_to_ctx(&ctx, message, message_len);

    uint8_t hash[32];

    uint32_t num_blocks = (mask_len + 31) / 32;
    for (uint32_t i = 0; i < num_blocks; i++)
    {
        SHA256_CTX ctx_;
        mbedtls_sha256_init(&ctx_);
        mbedtls_sha256_clone(&ctx_, &ctx);

        uint32_t ctr_be;
        REVERSE32(i, ctr_be);

        sha256_add_to_ctx(&ctx_, (const uint8_t*)&ctr_be, 4);
        sha256_finalize_32(&ctx_, hash);

        memcpy(out + i * 32, hash, min_u32(mask_len - i * 32, 32u));
    }

    mbedtls_sha256_free(&ctx);
}
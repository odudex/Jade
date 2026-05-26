#include "xmss.h"

void xmss_treehash(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t target_height, uint32_t start_idx, uint8_t* out)
{
    if (target_height == 0) 
    {
        wots_pk_gen(sk_seed, hash_ctx, adrs, start_idx, 0, out);
        return;
    }

    uint8_t left[N], right[N];
    xmss_treehash(sk_seed, hash_ctx, adrs, target_height - 1, start_idx, left);
    xmss_treehash(sk_seed, hash_ctx, adrs, target_height - 1, start_idx + (1 << (target_height - 1)), right);

    setTypeAndClear(adrs, SL_TREE);
    setTreeHeight(adrs, target_height);
    setTreeIndex(adrs, start_idx >> target_height);

    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);
    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, left, N);
    sha256_add_to_ctx(&ctx, right, N);

    sha256_finalize(&ctx, out);
}

void xmss_root(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint8_t* out)
{
    return xmss_treehash(sk_seed, hash_ctx, adrs, h_prime, 0, out);
}

void xmss_auth_path(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint32_t idx, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end)
{
    for (uint32_t i = 0; i < h_prime; i++)
    {
        uint32_t sibling_start = ((idx ^ (1 << i)) >> i) << i;
        xmss_treehash(sk_seed, hash_ctx, adrs, i, sibling_start, out + i*N);
        if (cb) cb((uint16_t)(prog_start + (uint32_t)(prog_end - prog_start) * (i + 1) / h_prime), cb_ud);
    }
}

void xmss_pk_from_sig(const uint8_t* wots_sig, const uint8_t* auth, const uint8_t* message, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint32_t idx, uint8_t* out)
{
    wots_pk_from_sig(wots_sig, message, N, pk_root, hash_ctx, adrs, idx, 0, 1, out);

    for (uint32_t i = 0; i < h_prime; i++)
    {
        setTypeAndClear(adrs, SL_TREE);
        setTreeHeight(adrs, i + 1);
        setTreeIndex(adrs, idx >> 1);
        uint8_t auth_node[N];
        memcpy(auth_node, auth + N*i, N);

        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);
        sha256_add_to_ctx(&ctx, adrs, 32);
        if ((idx & 1) == 0)
        {
            sha256_add_to_ctx(&ctx, out, N);
            sha256_add_to_ctx(&ctx, auth_node, N);
        }
        else
        {
            sha256_add_to_ctx(&ctx, auth_node, N);
            sha256_add_to_ctx(&ctx, out, N);
        }

        sha256_finalize(&ctx, out);
        idx >>= 1;
    }
}

void xmss_sign(const uint8_t* message, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint32_t idx, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end)
{
    uint16_t mid = (uint16_t)(prog_start + (uint32_t)(prog_end - prog_start) * 40 / 100);
    wots_sign(message, N, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, idx, 0, 1, out, cb, cb_ud, prog_start, mid);
    xmss_auth_path(sk_seed, hash_ctx, adrs, h_prime, idx, out + WOTS_SIGN_LEN, cb, cb_ud, mid, prog_end);
}
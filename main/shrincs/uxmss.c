#include "uxmss.h"

// Stateful-tree leaf for keypair kp (1..HSF+1): looked up from leaf_cache when
// available, else computed (and optionally captured into leaf_capture).
// Cache layout: leaf of keypair kp lives at (kp-1)*N; total (HSF+1)*N bytes.
static void uxmss_leaf(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint8_t* out,
    const uint8_t* leaf_cache, uint8_t* leaf_capture)
{
    if (leaf_cache)
    {
        memcpy(out, leaf_cache + (keypair - 1) * N, N);
        return;
    }
    wots_pk_gen(sk_seed, hash_ctx, adrs, keypair, 1, out);
    if (leaf_capture)
    {
        memcpy(leaf_capture + (keypair - 1) * N, out, N);
    }
}

void uxmss_treehash(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t start_level, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end,
    const uint8_t* leaf_cache, uint8_t* leaf_capture)
{
    uint8_t curr[N];
    uint32_t total = HSF - start_level + 1;
    uint32_t done = 0;

    uxmss_leaf(sk_seed, hash_ctx, adrs, HSF + 1, curr, leaf_cache, leaf_capture);
    done++;
    if (cb) cb((uint16_t)(prog_start + (uint32_t)(prog_end - prog_start) * done / total), cb_ud);

    for (int32_t level = (int32_t)(HSF - 1); level >= (int32_t)start_level; level--)
    {
        uint8_t left[N];
        uxmss_leaf(sk_seed, hash_ctx, adrs, (uint32_t)(level + 1), left, leaf_cache, leaf_capture);
        done++;
        if (cb) cb((uint16_t)(prog_start + (uint32_t)(prog_end - prog_start) * done / total), cb_ud);

        setTypeAndClear(adrs, SF_TREE);
        setTreeHeight(adrs, (uint32_t)(HSF - level));
        setTreeIndex(adrs, 0);

        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, left, N);
        sha256_add_to_ctx(&ctx, curr, N);
        sha256_finalize(&ctx, curr);
    }

    memcpy(out, curr, N);
}

void uxmss_root(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* out, uint8_t* leaf_capture)
{
    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    uxmss_treehash(sk_seed, hash_ctx, adrs, 0, out, NULL, NULL, 0, 0, NULL, leaf_capture);
}

void uxmss_auth_path(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t q, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end,
    const uint8_t* leaf_cache)
{
    // uint8_t auth[(q > HSF ? q - 1 : q) * N];

    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);

    uint16_t mid = (uint16_t)(prog_start + (uint32_t)(prog_end - prog_start) * (HSF - q) / HSF);

    if (q <= HSF)
    {
        if (q == HSF)
        {
            uxmss_leaf(sk_seed, hash_ctx, adrs, HSF + 1, out, leaf_cache, NULL);
        }
        else
        {

            uxmss_treehash(sk_seed, hash_ctx, adrs, q, out, cb, cb_ud, prog_start, mid, leaf_cache, NULL);
        }
        if (cb) cb((uint16_t)(mid + (uint32_t)(prog_end - mid) * 1 / q), cb_ud);

        for (uint32_t i = 1; i < q; i++)
        {
            uxmss_leaf(sk_seed, hash_ctx, adrs, q - i, out + N*i, leaf_cache, NULL);
            if (cb) cb((uint16_t)(mid + (uint32_t)(prog_end - mid) * (i + 1) / q), cb_ud);
        }
    }
    else {
        for (uint32_t i = 0; i < HSF; i++)
        {
            uxmss_leaf(sk_seed, hash_ctx, adrs, HSF - i, out + N*i, leaf_cache, NULL);
            if (cb) cb((uint16_t)(prog_start + (uint32_t)(prog_end - prog_start) * (i + 1) / HSF), cb_ud);
        }
    }
}

void uxmss_pk_from_sig(const uint8_t* wots_sig, const uint8_t* auth, const uint8_t* message, uint32_t message_len, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t q, uint32_t swn, uint8_t* out)
{
    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    wots_pk_from_sig(wots_sig, message, message_len, pk_root, hash_ctx, adrs, q, 1, 0, swn, out);

    setTypeAndClear(adrs, SF_TREE);
    if (q <= HSF) 
    {
        setTreeHeight(adrs, HSF - (q - 1));
        setTreeIndex(adrs, 0);

        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, out, N);
        sha256_add_to_ctx(&ctx, auth, N);

        sha256_finalize(&ctx, out);

        for (uint32_t i = 1; i < q; i++)
        {
            setTreeHeight(adrs, HSF - (q - 1 - i));
            setTreeIndex(adrs, 0);

            ctx = *hash_ctx;
            sha256_add_to_ctx(&ctx, adrs, 32);
            sha256_add_to_ctx(&ctx, auth + N*i, N);
            sha256_add_to_ctx(&ctx, out, N);

            sha256_finalize(&ctx, out);
        }
    }
    else 
    {
        for (uint32_t i = 0; i < HSF; i++)
        {
            setTreeHeight(adrs, i + 1);
            setTreeIndex(adrs, 0);

            SHA256_CTX ctx;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_clone(&ctx, hash_ctx);

            sha256_add_to_ctx(&ctx, adrs, 32);
            sha256_add_to_ctx(&ctx, auth + N*i, N);
            sha256_add_to_ctx(&ctx, out, N);

            sha256_finalize(&ctx, out);
        }
    }
}

void uxmss_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX *hash_ctx, uint8_t* adrs, uint32_t q, uint32_t swn, uint8_t* out)
{
    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);

    wots_sign(message, message_len, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, q, 1, 0, swn, out, NULL, NULL, 0, 0);
    uxmss_auth_path(sk_seed, hash_ctx, adrs, q, out + WOTS_SIGN_LEN, NULL, NULL, 0, 0, NULL);
}

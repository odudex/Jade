#include "shrincs.h"

void generate_random_bytes(uint8_t* buffer, size_t length) {
    get_random(buffer, length);
}

void parse_idx(const uint8_t* xof, uint32_t* idx_tree, uint32_t* idx_leaf)
{
    uint32_t idx = extract_bits(xof, xof_offset_bits, HSL);

    for (uint32_t layer = 0; layer < D; layer++)
    {
        idx_leaf[layer] = idx & ((1 << H_PRIME) - 1);
        idx >>= H_PRIME;
        idx_tree[layer] = idx;
    }
}

void shrincs_key_gen(PublicKey* out_pk, SecretKey* out_sk, State* out_state) 
{
    uint8_t seed[3*N];
    generate_random_bytes(seed, 3*N);

    shrincs_restore(seed, out_pk, out_sk, out_state, NULL);

    out_state->valid = 1;
}

void shrincs_restore(const uint8_t* seed, PublicKey* out_pk, SecretKey* out_sk, State* out_state, uint8_t* leaf_capture)
{
    uint8_t sk_seed[N];
    uint8_t sk_prf[N];
    uint8_t pk_seed[N];

    memcpy(sk_seed, seed, N);
    memcpy(sk_prf, seed + N, N);
    memcpy(pk_seed, seed + 2*N, N);

    uint8_t adrs[32] = {0};

    SHA256_CTX hash_ctx;
    sha256_init_ctx(&hash_ctx);

    sha256_add_to_ctx(&hash_ctx, pk_seed, N);
    // Add zeros
    sha256_add_to_ctx(&hash_ctx, adrs, 32);
    sha256_add_to_ctx(&hash_ctx, adrs, 16);

    uint8_t pk_sf[N];
    uxmss_root(sk_seed, &hash_ctx, adrs, pk_sf, leaf_capture);

    setLayerAddress(adrs, D - 1);
    setTreeAddress(adrs, 0, 0);
    uint8_t pk_sl[N];
    xmss_root(sk_seed, &hash_ctx, adrs, H_PRIME, pk_sl);

    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    setTypeAndClear(adrs, ROOT);
    uint8_t pk_root[N];

    SHA256_CTX ctx;
    sha256_init_ctx(&ctx);
    sha256_copy_ctx(&ctx, &hash_ctx);

    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, pk_sf, N);
    sha256_add_to_ctx(&ctx, pk_sl, N);
    sha256_finalize(&ctx, pk_root);

    memcpy(out_sk->seed, sk_seed, N);
    memcpy(out_sk->prf, sk_prf, N);
    memcpy(out_sk->sf, pk_sf, N);
    memcpy(out_sk->sl, pk_sl, N);
    memcpy(out_sk->pk.seed, pk_seed, N);
    memcpy(out_sk->pk.root, pk_root, N);
    
    memcpy(out_pk->seed, pk_seed, N);
    memcpy(out_pk->root, pk_root, N);

    out_state->q = 0;
    out_state->valid = 0;
}

uint32_t shrincs_sign_stateful(const uint8_t* message, uint32_t message_len, SecretKey* sk, State* state, uint32_t swn, uint8_t* out, shrincs_progress_cb cb, void *cb_userdata,
    const uint8_t* leaf_cache)
{
    if (!state->valid) {
        return 0;
    }

    uint32_t q = state->q + 1;
    if (q > HSF + 1)
    {
        return 0;
    }

    uint8_t adrs[32] = {0};

    SHA256_CTX hash_ctx;
    sha256_init_ctx(&hash_ctx);

    sha256_add_to_ctx(&hash_ctx, sk->pk.seed, N);
    // Add zeros
    sha256_add_to_ctx(&hash_ctx, adrs, 32);
    sha256_add_to_ctx(&hash_ctx, adrs, 16);

    memcpy(out, sk->sl, N);

    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    // Progress split: SHRINCS_B auth path (W=256, 141 wots_pk_gen calls) dominates time.
    // SHRINCS_L grinding (4M iters) dominates. Allocate accordingly.
#if defined(SHRINCS_B) || defined(SHRINCS_B32)
    wots_sign(message, message_len, sk->seed, sk->prf, sk->pk.seed, sk->pk.root, &hash_ctx, adrs, q, 1, 0, swn, out + N, cb, cb_userdata, 0, 30);
    uxmss_auth_path(sk->seed, &hash_ctx, adrs, q, out + N + WOTS_SIGN_LEN, cb, cb_userdata, 30, 1000, leaf_cache);
#else // SHRINCS_L: grinding dominates
    wots_sign(message, message_len, sk->seed, sk->prf, sk->pk.seed, sk->pk.root, &hash_ctx, adrs, q, 1, 0, swn, out + N, cb, cb_userdata, 0, 800);
    uxmss_auth_path(sk->seed, &hash_ctx, adrs, q, out + N + WOTS_SIGN_LEN, cb, cb_userdata, 800, 1000, leaf_cache);
#endif

    state->q = q;
    return 1;
}

uint32_t shrincs_sign_stateless(const uint8_t* message, uint32_t message_len, SecretKey* sk, uint32_t swn, uint8_t* out, shrincs_progress_cb cb, void *cb_userdata)
{
    uint8_t adrs[32] = {0};

    SHA256_CTX hash_ctx;
    sha256_init_ctx(&hash_ctx);

    sha256_add_to_ctx(&hash_ctx, sk->pk.seed, N);
    // Add zeros
    sha256_add_to_ctx(&hash_ctx, adrs, 32);
    sha256_add_to_ctx(&hash_ctx, adrs, 16);

    uint8_t digest[32];

    memcpy(out, sk->sf, N);

    if (!pors_sign(message, message_len, sk->seed, sk->prf, sk->pk.seed, sk->pk.root, &hash_ctx, adrs, digest, out + N))
    {
        return 0;
    }
    if (cb) cb(300, cb_userdata);  // ~30% after PORS signing

    uint32_t indices[K];
    uint8_t xof_out[xof_block_idx * 32];

    pors_msg_to_indices(digest, adrs, &hash_ctx, indices, xof_out);

    uint32_t tree_idx[D];
    uint32_t leaf_idx[D];
    parse_idx(xof_out, tree_idx, leaf_idx);

    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, tree_idx[0] * (1 << H_PRIME) + leaf_idx[0]);
    uint8_t msg[N];
    pors_pk_from_sig(out + N, indices, &hash_ctx, adrs, msg);
    if (cb) cb(450, cb_userdata);  // ~45% after index computation

    for (uint32_t layer = 0; layer < D; layer++)
    {
        setLayerAddress(adrs, layer);
        setTreeAddress(adrs, 0, tree_idx[layer]);
        xmss_sign(msg, sk->seed, sk->prf, sk->pk.seed, sk->pk.root, &hash_ctx, adrs, H_PRIME, leaf_idx[layer], swn, out + N + PORS_SIGN_LEN + XMSS_SIGN_LEN * layer, cb, cb_userdata, 450 + 500 * layer / D, 450 + 500 * (layer + 1) / D);

        if (layer < D - 1)
        {
            xmss_root(sk->seed, &hash_ctx, adrs, H_PRIME, msg);
        }
    }

    return 1;
}

uint32_t shrincs_verify_stateful(const uint8_t* message, uint32_t message_len, const uint8_t* sig, uint32_t sig_len, PublicKey* pk)
{
    uint8_t adrs[32] = {0};
    uint8_t sl[N];
    memcpy(sl, sig, N);

    const uint8_t* uxmss_sig = sig + N;

    uint32_t auth_len = sig_len - N - WOTS_SIGN_LEN;

    if (auth_len % N != 0) 
    {
        return 0;
    }

    uint32_t q_raw = auth_len / N;
    if (q_raw < 1 || q_raw > HSF)
    {
        return 0;
    }

    uint32_t last_sf_level = !(q_raw < HSF);

    SHA256_CTX hash_ctx;
    sha256_init_ctx(&hash_ctx);

    sha256_add_to_ctx(&hash_ctx, pk->seed, N);
    // Add zeros
    sha256_add_to_ctx(&hash_ctx, adrs, 32);
    sha256_add_to_ctx(&hash_ctx, adrs, 16);

    for (int j = 0; j < (last_sf_level ? 2 : 1); j++)
    {
        uint8_t sf[N];
        uxmss_pk_from_sig(uxmss_sig, uxmss_sig + WOTS_SIGN_LEN, message, message_len, pk->root, &hash_ctx, adrs, last_sf_level ? HSF + j : q_raw, SWN, sf);

        uint8_t root[N];
        setTypeAndClear(adrs, ROOT);

        SHA256_CTX ctx;
        sha256_init_ctx(&ctx);
        sha256_copy_ctx(&ctx, &hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, sf, N);
        sha256_add_to_ctx(&ctx, sl, N);
        sha256_finalize(&ctx, root);

        uint32_t is_valid = memcmp(root, pk->root, N) == 0;

        if (is_valid)
        {
            return 1;
        }
    }

    return 0;
}

uint32_t shrincs_verify_stateless(const uint8_t* message, uint32_t message_len, const uint8_t* sig, PublicKey* pk)
{
    uint8_t adrs[32] = {0};
    uint8_t sf[N];

    memcpy(sf, sig, N);
    uint32_t offset = N;

    const uint8_t* pors_sig = sig + offset;
    offset += PORS_SIGN_LEN;

    const uint8_t* r = pors_sig;

    SHA256_CTX hash_ctx;
    sha256_init_ctx(&hash_ctx);

    sha256_add_to_ctx(&hash_ctx, pk->seed, N);
    // Add zeros
    sha256_add_to_ctx(&hash_ctx, adrs, 32);
    sha256_add_to_ctx(&hash_ctx, adrs, 16);

    SHA256_CTX ctx;
    sha256_init_ctx(&ctx);
    sha256_copy_ctx(&ctx, &hash_ctx);

    setTypeAndClear(adrs, SL_H_MSG);
    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, r, R_LEN);
    sha256_add_to_ctx(&ctx, pk->root, N);
    sha256_add_to_ctx(&ctx, message, message_len);

    uint8_t digest[32];
    sha256_finalize_32(&ctx, digest);

    uint32_t indices[K];
    uint8_t xof_out[xof_block_idx * 32];

    pors_msg_to_indices(digest, adrs, &hash_ctx, indices, xof_out);

    Tuple32_t A[M_MAX];
    uint32_t A_len;
    if (!pors_octopus(indices, A, &A_len))
    {
        return 0;
    }

    uint32_t offset_back = PORS_SIGN_LEN - N;
    for (uint32_t i = A_len; i < M_MAX; i++)
    {
        uint32_t is_all_zeros = 1;

        for (uint32_t j = 0; j < N; j++) {
            if (pors_sig[offset_back + j] != 0) {
                is_all_zeros = 0;
                break;
            }
        }

        offset_back -= N;

        if (!is_all_zeros)
        {
            return 0;
        }
    }

    uint32_t tree_idx[D];
    uint32_t leaf_idx[D];
    parse_idx(xof_out, tree_idx, leaf_idx);

    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, tree_idx[0] * (1 << H_PRIME) + leaf_idx[0]);

    uint8_t msg[N];
    
    pors_pk_from_sig(pors_sig, indices, &hash_ctx, adrs, msg);

    for (uint32_t layer = 0; layer < D; layer++)
    {
        const uint8_t* xmss_sig = sig + offset;
        offset += XMSS_SIGN_LEN;
        setLayerAddress(adrs, layer);
        setTreeAddress(adrs, 0, tree_idx[layer]);
 
        xmss_pk_from_sig(xmss_sig, xmss_sig + WOTS_SIGN_LEN, msg, pk->root, &hash_ctx, adrs, H_PRIME, leaf_idx[layer], SWN, msg);
    }

    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    uint8_t root[N];
    setTypeAndClear(adrs, ROOT);

    ctx = hash_ctx;
    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, sf, N);
    sha256_add_to_ctx(&ctx, msg, N);
    sha256_finalize(&ctx, root);

    return memcmp(root, pk->root, N) == 0;
}

uint32_t shrincs_verify(const uint8_t* message, uint32_t message_len, const uint8_t* sig, uint32_t sig_len, PublicKey* pk)
{
    if (sig_len <= MAX_SF_SIZE)
    {
        return shrincs_verify_stateful(message, message_len, sig, sig_len, pk);
    }
    else
    {
        return shrincs_verify_stateless(message, message_len, sig, pk);
    }
}
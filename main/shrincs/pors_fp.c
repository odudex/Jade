#include "pors_fp.h"

uint32_t extract_bits(const uint8_t* message, uint32_t start_bit_idx, uint32_t bits_amount)
{
    uint32_t res = 0;
    for (uint32_t i = 0; i < bits_amount; i++)
    {
        uint32_t bit_idx = start_bit_idx + i;
        uint32_t byte_idx = bit_idx / 8;
        uint32_t bit_in_byte = bit_idx % 8;
            
        uint32_t bit = (message[byte_idx] >> (7 - bit_in_byte)) & 1;
        res = (res << 1) | bit;
    }
    return res;
}

uint32_t uint32_arr_have(uint32_t* arr, uint32_t arr_size, uint32_t elem)
{
    for (uint32_t i = 0; i < arr_size; i++)
    {
        if (arr[i] == elem)
        {
            return 1;
        }
    }
        
    return 0;
}

void pors_msg_to_indices(const uint8_t* message, uint8_t* adrs, SHA256_CTX* hash_ctx, uint32_t* indices_out, uint8_t* xof_out)
{
    uint8_t block[32];
    uint32_t xof_offset = 0;

    uint32_t indices_amount = 0;

    setTypeAndClear(adrs, PORS_XOF);
    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);

    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, message, 32);

    for (uint32_t blk = 0; blk < UINT32_MAX; blk++)
    {
        SHA256_CTX ctx_;
        mbedtls_sha256_init(&ctx_);
        mbedtls_sha256_clone(&ctx_, &ctx);

        uint32_t ctr_be;
        REVERSE32(blk, ctr_be);

        sha256_add_to_ctx(&ctx_, (const uint8_t*)&ctr_be, 4);
        sha256_finalize_32(&ctx_, block);

        if (blk < xof_block_idx)
        {
            memcpy(xof_out + xof_offset, block, 32);
            xof_offset += 32;
        }

        for (uint32_t i = 0; i < c_shrincs; i++)
        {
            if (indices_amount == K) break;
            uint32_t candidate = extract_bits(block, i * B, B);
            if (candidate < T && !uint32_arr_have(indices_out, indices_amount, candidate))
            {
                indices_out[indices_amount] = candidate;
                indices_amount++;
            }
        }

        if (blk >= xof_block_idx && indices_amount == K)
        {
            for (uint32_t i = 0; i < K - 1; i++) {
                for (uint32_t j = 0; j < K - i - 1; j++) {
                    if (indices_out[j] > indices_out[j + 1]) {
                        uint32_t temp = indices_out[j];
                        indices_out[j] = indices_out[j + 1];
                        indices_out[j + 1] = temp;
                    }
                }
            }
            return;
        }
    }

    // throw std::runtime_error("Unable to find valid indices for PORS+FP");
}

uint32_t pors_octopus(uint32_t* indices, Tuple32_t* A_out, uint32_t* A_len_out)
{
    uint32_t s = T - (1 << (B - 1));

    Tuple32_t I[K];
    uint32_t I_len = 0;

    Tuple32_t P[K];
    uint32_t P_len = 0;

    *A_len_out = 0;

    for (uint32_t j = 0; j < K; j++)
    {
        uint32_t i = indices[j];

        if (i < 2 * s)
        {
            I[I_len].a = 0;
            I[I_len].b = i;
            I_len++;
        }
        else
        {
            P[P_len].a = 1;
            P[P_len].b = i - s;
            P_len++;
        }
    }

    for (uint32_t current_lvl = 0; current_lvl < B; current_lvl++)
    {
        Tuple32_t P_next[K];
        uint32_t P_next_len = 0;

        uint32_t i = 0;
        while (i < I_len)
        {
            uint32_t idx = I[i].b;
            uint32_t sib = idx ^ 1;

            if (i + 1 < I_len && I[i + 1].b == sib)
            {
                i += 2;
            }
            else
            {
                if (*A_len_out >= M_MAX) {
                    return 0;
                }
                A_out[*A_len_out].a = current_lvl;
                A_out[*A_len_out].b = sib;
                (*A_len_out)++;
                i++;
            }

            P_next[P_next_len].a = current_lvl + 1;
            P_next[P_next_len].b = idx >> 1;
            P_next_len++;
        }

        for (uint32_t m = 0; m < P_next_len; m++) {
            I[m] = P_next[m];
        }
        I_len = P_next_len;

        for (uint32_t m = 0; m < P_len; m++) {
            I[I_len + m] = P[m];
        }
        I_len += P_len;

        P_len = 0;

        if (I_len == 1 && I[0].b == 0)
        {
            break;
        }
    }

    return 1;
}

void pors_grind(const uint8_t* message, uint32_t message_len, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, uint8_t* adrs, uint8_t* opt_rand, SHA256_CTX* hash_ctx, uint32_t* indices_out, uint8_t* digest_out, uint8_t* r_out)
{
    setTypeAndClear(adrs, SL_H_MSG);

    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);
    sha256_add_to_ctx(&ctx, adrs, 32);

    Tuple32_t A[M_MAX];
    uint32_t A_len;

    unsigned char xof_out[xof_block_idx * 32];

    for (uint64_t ctr = 0; ctr <= UINT32_MAX; ctr++)
    {
        A_len = 0;

        prf_msg(sk_prf, pk_seed, opt_rand, message, message_len, 1, ctr, R_LEN, r_out);

        SHA256_CTX ctx_;
        mbedtls_sha256_init(&ctx_);
        mbedtls_sha256_clone(&ctx_, &ctx);

        sha256_add_to_ctx(&ctx_, r_out, R_LEN);
        sha256_add_to_ctx(&ctx_, pk_root, N);
        sha256_add_to_ctx(&ctx_, message, message_len);
        sha256_finalize_32(&ctx_, digest_out);

        pors_msg_to_indices(digest_out, adrs, hash_ctx, indices_out, xof_out);
        if (pors_octopus(indices_out, A, &A_len))
        { 
            break;
        }
    }
}

void pors_sk_gen(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t leaf_idx, uint8_t* out)
{
    setTypeAndClear(adrs, PORS_PRF);
    setKeyPairAddress(adrs, 0);
    setTreeIndex(adrs, leaf_idx);

    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);

    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, sk_seed, N);
    sha256_finalize(&ctx, out);
}

void pors_treehash(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t target_height, uint32_t idx, uint8_t* out)
{
    uint32_t s = T - (1 << (B - 1));

    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);

    uint8_t sk[N];

    if (target_height == 0)
    {
        pors_sk_gen(sk_seed, hash_ctx, adrs, idx, sk);
        setTypeAndClear(adrs, PORS_HASH);
        setKeyPairAddress(adrs, 0);
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, idx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, sk, N);
        sha256_finalize(&ctx, out);

        return;
    }
    else if (target_height == 1 && idx >= s)
    {
        uint32_t leaf_idx = s + idx;
        pors_sk_gen(sk_seed, hash_ctx, adrs, leaf_idx, sk);
        setTypeAndClear(adrs, PORS_HASH);
        setKeyPairAddress(adrs, 0);
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, leaf_idx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, sk, N);
        sha256_finalize(&ctx, out);

        return;
    }

    uint8_t left[N];
    uint8_t right[N];

    pors_treehash(sk_seed, hash_ctx, adrs, target_height - 1, 2 * idx, left);
    pors_treehash(sk_seed, hash_ctx, adrs, target_height - 1, 2 * idx + 1, right);

    setTypeAndClear(adrs, PORS_TREE);
    setKeyPairAddress(adrs, 0);
    setTreeHeight(adrs, target_height);
    setTreeIndex(adrs, idx);

    ctx = *hash_ctx;
    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, left, N);
    sha256_add_to_ctx(&ctx, right, N);
    sha256_finalize(&ctx, out);
}

uint32_t pors_auth_path(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t* indices, uint32_t* A_len, uint8_t* out)
{
    Tuple32_t A[M_MAX];
    *A_len = 0;

    if(!pors_octopus(indices, A, A_len))
    {
        return 0;
    }

    for (uint32_t i = 0; i < *A_len; i++)
    {
        uint32_t lvl = A[i].a;
        uint32_t idx = A[i].b;

        pors_treehash(sk_seed, hash_ctx, adrs, lvl, idx, out + N*i);
    }

    return 1;
}

uint32_t pors_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* digest_out, uint8_t* out)
{
    // Or random(n)
    uint8_t opt_rand[N];
    memcpy(opt_rand, pk_seed, N);

    uint32_t indices[K];
    pors_grind(message, message_len, sk_prf, pk_seed, pk_root, adrs, opt_rand, hash_ctx, indices, digest_out, out);
    uint32_t offset = R_LEN;

    for (uint32_t i = 0; i < K; i++)
    {
        pors_sk_gen(sk_seed, hash_ctx, adrs, indices[i], out + offset);
        offset += N;
    }

    uint32_t A_len;

    return pors_auth_path(sk_seed, hash_ctx, adrs, indices, &A_len, out + offset);
}

void pors_pk_from_sig(const uint8_t* sig, uint32_t indices[K], SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* out)
{
    uint32_t offset = R_LEN;

    uint32_t s = T - (1 << (B - 1));

    uint8_t sk_i[N];

    PorsNode_t I[K];
    uint32_t I_len = 0;
    
    PorsNode_t P[K];
    uint32_t P_len = 0;

    uint8_t val[N];

    for (uint32_t i = 0; i < K; i++)
    {
        memcpy(sk_i, sig + offset, N);
        offset += N;

        setTypeAndClear(adrs, PORS_HASH);
        setKeyPairAddress(adrs, 0);
        setTreeHeight(adrs, 0);
        setTreeIndex(adrs, indices[i]);

        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, sk_i, N);
        sha256_finalize(&ctx, val);

        if (indices[i] < (s << 1))
        {
            I[I_len].lvl = 0;
            I[I_len].idx = indices[i];
            memcpy(I[I_len].val, val, N);
            I_len++;
        }
        else 
        {
            P[P_len].lvl = 1;
            P[P_len].idx = indices[i] - s;
            memcpy(P[P_len].val, val, N);
            P_len++;
        }
    }

    uint8_t parent_val[N];
    uint8_t auth_val[N];

    for (uint32_t cur_lvl = 0; cur_lvl < B; cur_lvl++)
    {
        uint8_t paired[K];
        memset(paired, 0, sizeof(paired));

        for (uint32_t i = 0; i < I_len; i++)
        {
            if (i + 1 < I_len && I[i + 1].idx == (I[i].idx ^ 1))
            {
                paired[i] = 1;
                paired[i + 1] = 1;
            }
        }
        
        PorsNode_t P_next[K];
        uint32_t P_next_len = 0;

        for (uint32_t i = 0; i < I_len; i++)
        {
            uint32_t idx = I[i].idx;

            if (paired[i] && (idx & 1) == 0)
            {
                continue;
            }

            setTypeAndClear(adrs, PORS_TREE);
            setKeyPairAddress(adrs, 0);
            setTreeHeight(adrs, cur_lvl + 1);
            setTreeIndex(adrs, idx >> 1);

            SHA256_CTX ctx;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_clone(&ctx, hash_ctx);

            sha256_add_to_ctx(&ctx, adrs, 32);

            if (paired[i])
            {
                sha256_add_to_ctx(&ctx, I[i-1].val, N);
                sha256_add_to_ctx(&ctx, I[i].val, N);
            }
            else
            {
                memcpy(auth_val, sig + offset, N);
                offset += N;
                if ((idx & 1) == 0) 
                {
                    sha256_add_to_ctx(&ctx, I[i].val, N);
                    sha256_add_to_ctx(&ctx, auth_val, N);
                }
                else
                {
                    sha256_add_to_ctx(&ctx, auth_val, N);
                    sha256_add_to_ctx(&ctx, I[i].val, N);
                }
            }
            sha256_finalize(&ctx, parent_val);

            P_next[P_next_len].lvl = cur_lvl + 1;
            P_next[P_next_len].idx = idx >> 1;
            memcpy(P_next[P_next_len].val, parent_val, N);
            P_next_len++;
        }

        for (uint32_t m = 0; m < P_next_len; m++) {
            I[m] = P_next[m];
        }
        I_len = P_next_len;

        for (uint32_t m = 0; m < P_len; m++) {
            I[I_len + m] = P[m];
        }
        I_len += P_len;

        P_len = 0;

        if (I_len == 1 && I[0].idx == 0)
        {
            break;
        }
    }

    setTypeAndClear(adrs, PORS_PK);

    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);
    
    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, I[0].val, N);
    sha256_finalize(&ctx, out);
}
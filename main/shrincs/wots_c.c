#include "wots_c.h"

void base_w(const uint8_t* message, uint8_t* out_buffer) 
{
    int w_log = __builtin_ctz(W);
    int w_mod = W - 1;

    int in_idx = 0;
    int bits = 0;
    int total = 0;

    for (uint32_t i = 0; i < L; i++)
    {
        if (bits == 0) 
        {
            total = message[in_idx];
            in_idx++;
            bits = 8;
        }
        bits -= w_log;
        out_buffer[i] = (total >> bits) & (w_mod);
    }
}

void chain(const uint8_t* m, uint32_t start, uint32_t steps, SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* out) 
{
    memcpy(out, m, N);

    for (uint32_t i = start; i < start + steps; i++)
    {
        setHashAddress(adrs, i);
        
        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, out, N);
        sha256_finalize(&ctx, out);
    }
}

void wots_pk_gen(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint8_t* out)
{
    uint32_t WOTS_HASH, WOTS_PK, WOTS_PRF_TYPE;
    if (sf)
    {
        WOTS_HASH = SF_WOTS_HASH;
        WOTS_PK = SF_WOTS_PK;
        WOTS_PRF_TYPE = SF_WOTS_PRF;
    }
    else
    {
        WOTS_HASH = SL_WOTS_HASH;
        WOTS_PK = SL_WOTS_PK;
        WOTS_PRF_TYPE = SL_WOTS_PRF;
    }

    uint8_t pk[L][N];
    uint32_t steps = W - 1;

    for (uint32_t i = 0; i < L; i++)
    {
        setTypeAndClear(adrs, WOTS_PRF_TYPE);
        setKeyPairAddress(adrs, keypair);
        setChainAddress(adrs, i);
        
        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, sk_seed, N);

        uint8_t sk_i[N];
        sha256_finalize(&ctx, sk_i);

        setTypeAndClear(adrs, WOTS_HASH);
        setKeyPairAddress(adrs, keypair);
        setChainAddress(adrs, i);

        chain(sk_i, 0, steps, hash_ctx, adrs, pk[i]);
    }
    
    setTypeAndClear(adrs, WOTS_PK);
    setKeyPairAddress(adrs, keypair);

    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);

    sha256_add_to_ctx(&ctx, adrs, 32);

    for(uint32_t i = 0; i < L; i++)
    {
        sha256_add_to_ctx(&ctx, pk[i], N);
    }

    sha256_finalize(&ctx, out);
}

uint32_t wots_grind(const uint8_t* message, uint32_t message_len, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint8_t* msg_out, uint32_t sf, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end)
{
    if (sf)
    {
        setTypeAndClear(adrs, SF_WOTS_GRIND);
    }
    else
    {
        setTypeAndClear(adrs, SL_WOTS_GRIND);
    }

    setKeyPairAddress(adrs, keypair);
    
    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);
    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, message, message_len);

    unsigned char res[N];
    unsigned char tmp_msg[L];

    uint16_t prog_cur = prog_start;
    uint16_t prog_step = (uint16_t)((prog_end - prog_start) / 50);

    for (uint32_t ctr = 0; ctr < UINT32_MAX; ctr++)
    {
        if (cb && ctr % 100000 == 0 && prog_cur < prog_end)
        { 
            prog_cur += prog_step;
            cb(prog_cur, cb_ud);
        }

        uint32_t ctr_be;
        REVERSE32(ctr, ctr_be);
        SHA256_CTX ctx_;
        mbedtls_sha256_init(&ctx_);
        mbedtls_sha256_clone(&ctx_, &ctx);
        sha256_add_to_ctx(&ctx_, (const uint8_t*)&ctr_be, 4);
        sha256_finalize(&ctx_, res);

        base_w(res, tmp_msg);

        uint32_t sum = 0;
        for (uint32_t i = 0; i < L; i++) sum += tmp_msg[i];
        
        if (sum == SWN) 
        {
            memcpy(msg_out, tmp_msg, L);
            return ctr;
        }
    }
    
    return 0; // What should we return here?
}

uint32_t wots_digest(const uint8_t* message, uint32_t message_len, SHA256_CTX* hash_ctx, uint32_t ctr, uint8_t* adrs, uint32_t keypair, uint8_t* msg_out, uint32_t sf)
{
    if (sf)
    {
        setTypeAndClear(adrs, SF_WOTS_GRIND);
    }
    else
    {
        setTypeAndClear(adrs, SL_WOTS_GRIND);
    }

    setKeyPairAddress(adrs, keypair);

    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);
    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, message, message_len);

    uint32_t ctr_be;
    REVERSE32(ctr, ctr_be);
    sha256_add_to_ctx(&ctx, (const uint8_t*)&ctr_be, 4);

    uint8_t res[N];
    sha256_finalize(&ctx, res);

    base_w(res, msg_out);

    uint32_t sum = 0;
    for (uint32_t i = 0; i < L; i++) sum += msg_out[i];

    return sum == SWN;
    // return 1;
}

void wots_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint32_t is_internal, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end)
{
    uint32_t WOTS_HASH, WOTS_PRF_TYPE, H_MSG_TYPE;
    if (sf)
    {
        WOTS_HASH = SF_WOTS_HASH;
        WOTS_PRF_TYPE = SF_WOTS_PRF;
        H_MSG_TYPE = SF_H_MSG;
    }
    else
    {
        WOTS_HASH = SL_WOTS_HASH;
        WOTS_PRF_TYPE = SL_WOTS_PRF;
        H_MSG_TYPE = SL_H_MSG;
    }

    // Or random(n)
    uint8_t opt_rand[N];
    memcpy(opt_rand, pk_seed, N);
    uint8_t r[R_LEN];
    prf_msg(sk_prf, pk_seed, opt_rand, message, message_len, 0, 0, R_LEN, r);

    uint8_t digest[N];
    if (is_internal)
    {
        memcpy(digest, message, message_len);
    }
    else
    {
        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        setTypeAndClear(adrs, H_MSG_TYPE);
        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, r, R_LEN);
        sha256_add_to_ctx(&ctx, pk_root, N);
        sha256_add_to_ctx(&ctx, message, message_len);
        sha256_finalize(&ctx, digest);
    }

    uint8_t msg[L];
    uint16_t mid = (uint16_t)((uint32_t)prog_start + ((uint32_t)(prog_end - prog_start) * 8 / 10));
    uint32_t ctr = wots_grind(digest, N, hash_ctx, adrs, keypair, msg, sf, cb, cb_ud, prog_start, mid);
    cb(mid, cb_ud);

    memcpy(out, r, R_LEN);
    uint32_t offset = R_LEN;

    uint32_t ctr_be;
    REVERSE32(ctr, ctr_be);
    memcpy(out + offset, (const uint8_t*)&ctr_be, 4);
    offset += 4;

    for (uint32_t i = 0; i < L; i++)
    {
        setTypeAndClear(adrs, WOTS_PRF_TYPE);
        setKeyPairAddress(adrs, keypair);
        setChainAddress(adrs, i);

        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, sk_seed, N);

        uint8_t sk_i[N];
        sha256_finalize(&ctx, sk_i);

        setTypeAndClear(adrs, WOTS_HASH);
        setKeyPairAddress(adrs, keypair);
        setChainAddress(adrs, i);

        uint8_t tmp[N];
        chain(sk_i, 0, msg[i], hash_ctx, adrs, tmp);
        memcpy(out + offset, tmp, N);
        offset += N;

        if (cb) cb((uint16_t)(mid + (uint32_t)(prog_end - mid) * (i + 1) / L), cb_ud);
    }
}

uint32_t wots_pk_from_sig(const uint8_t* sig, const uint8_t* message, uint32_t message_len, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint32_t is_internal, uint8_t* out)
{
    uint32_t WOTS_HASH, WOTS_PK, H_MSG_TYPE;
    if (sf)
    {
        WOTS_HASH = SF_WOTS_HASH;
        WOTS_PK = SF_WOTS_PK;
        H_MSG_TYPE = SF_H_MSG;
    }
    else
    {
        WOTS_HASH = SL_WOTS_HASH;
        WOTS_PK = SL_WOTS_PK;
        H_MSG_TYPE = SL_H_MSG;
    }

    uint8_t r[R_LEN];
    memcpy(r, sig, R_LEN);
    uint32_t offset = R_LEN;

    uint32_t ctr;
    memcpy(&ctr, sig + offset, 4);
    REVERSE32(ctr, ctr);
    offset += 4;

    uint8_t digest[N];
    if (is_internal)
    {
        memcpy(digest, message, message_len);
    }
    else
    {
        SHA256_CTX ctx;
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_clone(&ctx, hash_ctx);

        setTypeAndClear(adrs, H_MSG_TYPE);
        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, r, R_LEN);
        sha256_add_to_ctx(&ctx, pk_root, N);
        sha256_add_to_ctx(&ctx, message, message_len);
        sha256_finalize(&ctx, digest);
    }

    uint8_t msg[L];
    uint32_t valid = wots_digest(digest, N, hash_ctx, ctr, adrs, keypair, msg, sf);

    if (!valid)
    {
        return 0;
    }

    uint32_t to_step = W - 1;
    uint8_t pk[L][N];
    uint8_t sig_i[N];
    for (uint32_t i = 0; i < L; i++)
    {
        setTypeAndClear(adrs, WOTS_HASH);
        setKeyPairAddress(adrs, keypair);
        setChainAddress(adrs, i);

        memcpy(sig_i, sig + offset, N);
        offset += N;
        
        chain(sig_i, msg[i], to_step - msg[i], hash_ctx, adrs, pk[i]);
    }

    setTypeAndClear(adrs, WOTS_PK);
    setKeyPairAddress(adrs, keypair);
    
    SHA256_CTX ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_clone(&ctx, hash_ctx);
    sha256_add_to_ctx(&ctx, adrs, 32);

    for(uint32_t i = 0; i < L; i++)
    {
        sha256_add_to_ctx(&ctx, pk[i], N);
    }

    sha256_finalize(&ctx, out);
    return 1;
}
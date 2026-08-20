#include "freertos/task.h"
#include "wots_c.h"
#include "../jade_tasks.h"

// Comment to make it multithread
#define CONFIG_FREERTOS_UNICORE 1

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
        sha256_init_ctx(&ctx);
        sha256_copy_ctx(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, out, N);
        sha256_finalize(&ctx, out);
    }
}

#ifndef CONFIG_FREERTOS_UNICORE

typedef struct {
    const uint8_t* sk_seed;
    SHA256_CTX*    hash_ctx;   // non-const: chain() requires non-const pointer
    uint8_t        adrs[32];   // independent copy — secondary modifies this freely
    uint32_t       keypair;
    uint32_t       wots_hash;
    uint32_t       wots_prf;
    uint8_t        (*pk)[N];   // pk[L][N] in caller's stack, each slot written by one worker
    volatile uint32_t next_i;  // shared work counter — workers pull the next free chain
    TaskHandle_t   primary_handle;
} wots_pk_chain_ctx_t;

// Pulls chain indices from the shared counter until all L chains are claimed.
// Self-balancing: if one core is slowed (eg. GUI repaints), the other picks up more chains.
static void wots_pk_chain_worker(wots_pk_chain_ctx_t* ctx, uint8_t* adrs)
{
    uint32_t i;
    while ((i = __atomic_fetch_add(&ctx->next_i, 1, __ATOMIC_RELAXED)) < L)
    {
        setTypeAndClear(adrs, ctx->wots_prf);
        setKeyPairAddress(adrs, ctx->keypair);
        setChainAddress(adrs, i);

        SHA256_CTX c;
        sha256_init_ctx(&c);
        sha256_copy_ctx(&c, ctx->hash_ctx);
        sha256_add_to_ctx(&c, adrs, 32);
        sha256_add_to_ctx(&c, ctx->sk_seed, N);
        uint8_t sk_i[N];
        sha256_finalize(&c, sk_i);

        setTypeAndClear(adrs, ctx->wots_hash);
        setKeyPairAddress(adrs, ctx->keypair);
        setChainAddress(adrs, i);

        chain(sk_i, 0, W - 1, ctx->hash_ctx, adrs, ctx->pk[i]);
    }
}

static void wots_pk_chain_secondary(void* arg)
{
    wots_pk_chain_ctx_t* ctx = (wots_pk_chain_ctx_t*)arg;
    wots_pk_chain_worker(ctx, ctx->adrs);
    xTaskNotifyGive(ctx->primary_handle);
    vTaskDelete(NULL);
}

#endif // !CONFIG_FREERTOS_UNICORE

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

#ifndef CONFIG_FREERTOS_UNICORE
    wots_pk_chain_ctx_t sctx = {
        .sk_seed       = sk_seed,
        .hash_ctx      = hash_ctx,
        .keypair       = keypair,
        .wots_hash     = WOTS_HASH,
        .wots_prf      = WOTS_PRF_TYPE,
        .pk            = pk,
        .next_i        = 0,
        .primary_handle = xTaskGetCurrentTaskHandle(),
    };
    memcpy(sctx.adrs, adrs, 32);

    const BaseType_t chain_task_ret = xTaskCreatePinnedToCore(
        wots_pk_chain_secondary, "wots_pk",
        2048, &sctx, JADE_TASK_PRIO_TEMPORARY,
        NULL, JADE_CORE_SECONDARY);

    // Primary pulls from the same pool; if task creation failed it just does all L chains
    wots_pk_chain_worker(&sctx, adrs);

    if (chain_task_ret == pdPASS)
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
#else
    for (uint32_t i = 0; i < L; i++)
    {
        setTypeAndClear(adrs, WOTS_PRF_TYPE);
        setKeyPairAddress(adrs, keypair);
        setChainAddress(adrs, i);

        SHA256_CTX ctx;
        sha256_init_ctx(&ctx);
        sha256_copy_ctx(&ctx, hash_ctx);

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, sk_seed, N);

        uint8_t sk_i[N];
        sha256_finalize(&ctx, sk_i);

        setTypeAndClear(adrs, WOTS_HASH);
        setKeyPairAddress(adrs, keypair);
        setChainAddress(adrs, i);

        chain(sk_i, 0, W - 1, hash_ctx, adrs, pk[i]);
    }
#endif
    
    setTypeAndClear(adrs, WOTS_PK);
    setKeyPairAddress(adrs, keypair);

    SHA256_CTX ctx;
    sha256_init_ctx(&ctx);
    sha256_copy_ctx(&ctx, hash_ctx);

    sha256_add_to_ctx(&ctx, adrs, 32);

    for(uint32_t i = 0; i < L; i++)
    {
        sha256_add_to_ctx(&ctx, pk[i], N);
    }

    sha256_finalize(&ctx, out);
}

#ifndef CONFIG_FREERTOS_UNICORE

typedef struct {
    const SHA256_CTX* ctx_base; // read-only: hash_ctx||adrs||message, cloned each iteration
    uint32_t swn;
    uint32_t start_ctr;         // first ctr value for this worker
    uint32_t step;              // ctr increment (2 for two workers)
    volatile int found;         // 0=searching, 1=found by someone
    uint32_t result_ctr;        // written by secondary before setting found=1
    uint8_t  result_msg[L];
    TaskHandle_t primary_handle;
} wots_grind_ctx_t;

static void wots_grind_secondary(void* arg)
{
    wots_grind_ctx_t* ctx = (wots_grind_ctx_t*)arg;
    uint32_t iters = 0;

    for (uint32_t ctr = ctx->start_ctr; ctr <= UINT32_MAX - ctx->step; ctr += ctx->step)
    {
        if (__atomic_load_n(&ctx->found, __ATOMIC_ACQUIRE))
            break;

        // Yield periodically so Core 1's idle task can run (prevents WDT starvation)
        if (++iters % 100000 == 0)
            vTaskDelay(1);

        uint32_t ctr_be;
        REVERSE32(ctr, ctr_be);
        SHA256_CTX ctx_;
        sha256_init_ctx(&ctx_);
        sha256_copy_ctx(&ctx_, ctx->ctx_base);
        sha256_add_to_ctx(&ctx_, (const uint8_t*)&ctr_be, 4);
        uint8_t res[N];
        sha256_finalize(&ctx_, res);

        uint8_t tmp_msg[L];
        base_w(res, tmp_msg);

        uint32_t sum = 0;
        for (uint32_t i = 0; i < L; i++) sum += tmp_msg[i];

        if (sum == ctx->swn)
        {
            // Write result BEFORE setting found (RELEASE ensures primary sees it after ACQUIRE)
            ctx->result_ctr = ctr;
            memcpy(ctx->result_msg, tmp_msg, L);
            __atomic_store_n(&ctx->found, 1, __ATOMIC_RELEASE);
            break;
        }
    }

    xTaskNotifyGive(ctx->primary_handle);
    vTaskDelete(NULL);
}

#endif // !CONFIG_FREERTOS_UNICORE

uint32_t wots_grind(const uint8_t* message, uint32_t message_len, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint8_t* msg_out, uint32_t sf, uint32_t swn, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end)
{
    if (sf)
        setTypeAndClear(adrs, SF_WOTS_GRIND);
    else
        setTypeAndClear(adrs, SL_WOTS_GRIND);

    setKeyPairAddress(adrs, keypair);

    // Build ctx_base once: hash_ctx || adrs || message — shared read-only between workers
    SHA256_CTX ctx_base;
    sha256_init_ctx(&ctx_base);
    sha256_copy_ctx(&ctx_base, hash_ctx);
    sha256_add_to_ctx(&ctx_base, adrs, 32);
    sha256_add_to_ctx(&ctx_base, message, message_len);

    uint16_t prog_cur = prog_start;
    uint16_t prog_step = (uint16_t)((prog_end - prog_start) / 50);

    uint32_t result_ctr = 0;
    bool primary_found = false;
    uint8_t primary_msg[L];

#ifndef CONFIG_FREERTOS_UNICORE
    // Dual-core: secondary task takes odd ctrs, primary takes even ctrs
    wots_grind_ctx_t pctx = {
        .ctx_base       = &ctx_base,
        .swn            = swn,
        .start_ctr      = 1,
        .step           = 2,
        .found          = 0,
        .primary_handle = xTaskGetCurrentTaskHandle(),
    };

    const BaseType_t task_ret = xTaskCreatePinnedToCore(
        wots_grind_secondary, "wots_gnd",
        4096, &pctx, JADE_TASK_PRIO_TEMPORARY,
        NULL, JADE_CORE_SECONDARY);

    if (task_ret != pdPASS) {
        // Fallback: secondary task unavailable, search all ctrs on this core
        for (uint32_t ctr = 0; ctr < UINT32_MAX; ctr++) {
            if (cb && ctr % 100000 == 0) {
                vTaskDelay(1);
                if (prog_cur < prog_end) { prog_cur += prog_step; cb(prog_cur, cb_ud); }
            }
            uint32_t ctr_be;
            REVERSE32(ctr, ctr_be);
            SHA256_CTX ctx_;
            sha256_init_ctx(&ctx_);
            sha256_copy_ctx(&ctx_, &ctx_base);
            sha256_add_to_ctx(&ctx_, (const uint8_t*)&ctr_be, 4);
            uint8_t res[N];
            sha256_finalize(&ctx_, res);
            uint8_t tmp_msg[L];
            base_w(res, tmp_msg);
            uint32_t sum = 0;
            for (uint32_t i = 0; i < L; i++) sum += tmp_msg[i];
            if (sum == swn) {
                result_ctr = ctr;
                memcpy(primary_msg, tmp_msg, L);
                primary_found = true;
                break;
            }
        }
        if (primary_found) memcpy(msg_out, primary_msg, L);
        sha256_free_ctx(&ctx_base);
        return result_ctr;
    }

    for (uint32_t ctr = 0; ctr <= UINT32_MAX - 2; ctr += 2)
    {
        if (__atomic_load_n(&pctx.found, __ATOMIC_ACQUIRE))
            break; // secondary found it

        if (cb && ctr % 200000 == 0)
        {
            if (prog_cur < prog_end) { prog_cur += prog_step; cb(prog_cur, cb_ud); }
        }

        uint32_t ctr_be;
        REVERSE32(ctr, ctr_be);
        SHA256_CTX ctx_;
        sha256_init_ctx(&ctx_);
        sha256_copy_ctx(&ctx_, &ctx_base);
        sha256_add_to_ctx(&ctx_, (const uint8_t*)&ctr_be, 4);
        uint8_t res[N];
        sha256_finalize(&ctx_, res);

        uint8_t tmp_msg[L];
        base_w(res, tmp_msg);

        uint32_t sum = 0;
        for (uint32_t i = 0; i < L; i++) sum += tmp_msg[i];

        if (sum == swn)
        {
            result_ctr    = ctr;
            memcpy(primary_msg, tmp_msg, L);
            primary_found = true;
            __atomic_store_n(&pctx.found, 1, __ATOMIC_RELEASE); // signal secondary to stop
            break;
        }
    }

    ulTaskNotifyTake(pdTRUE, portMAX_DELAY); // wait for secondary to exit

    if (primary_found)
    {
        memcpy(msg_out, primary_msg, L);
    }
    else if (pctx.found)
    {
        // secondary found it; reads are safe after ulTaskNotifyTake (implicit barrier)
        memcpy(msg_out, pctx.result_msg, L);
        result_ctr = pctx.result_ctr;
    }

#else
    // Unicore (QEMU): serial grinding
    for (uint32_t ctr = 0; ctr < UINT32_MAX; ctr++)
    {
        if (cb && ctr % 100000 == 0)
        {
            vTaskDelay(1);
            if (prog_cur < prog_end) { prog_cur += prog_step; cb(prog_cur, cb_ud); }
        }

        uint32_t ctr_be;
        REVERSE32(ctr, ctr_be);
        SHA256_CTX ctx_;
        sha256_init_ctx(&ctx_);
        sha256_copy_ctx(&ctx_, &ctx_base);
        sha256_add_to_ctx(&ctx_, (const uint8_t*)&ctr_be, 4);
        uint8_t res[N];
        sha256_finalize(&ctx_, res);

        uint8_t tmp_msg[L];
        base_w(res, tmp_msg);

        uint32_t sum = 0;
        for (uint32_t i = 0; i < L; i++) sum += tmp_msg[i];

        if (sum == swn)
        {
            result_ctr    = ctr;
            memcpy(primary_msg, tmp_msg, L);
            primary_found = true;
            break;
        }
    }

    if (primary_found) memcpy(msg_out, primary_msg, L);

#endif // CONFIG_FREERTOS_UNICORE

    sha256_free_ctx(&ctx_base);
    return result_ctr;
}

uint32_t wots_digest(const uint8_t* message, uint32_t message_len, SHA256_CTX* hash_ctx, uint32_t ctr, uint8_t* adrs, uint32_t keypair, uint8_t* msg_out, uint32_t sf, uint32_t swn)
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
    sha256_init_ctx(&ctx);
    sha256_copy_ctx(&ctx, hash_ctx);
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

    return sum == swn;
}

void wots_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint32_t is_internal, uint32_t swn, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end)
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
        sha256_init_ctx(&ctx);
        sha256_copy_ctx(&ctx, hash_ctx);

        setTypeAndClear(adrs, H_MSG_TYPE);
        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, r, R_LEN);
        sha256_add_to_ctx(&ctx, pk_root, N);
        sha256_add_to_ctx(&ctx, message, message_len);
        sha256_finalize(&ctx, digest);
    }

    uint8_t msg[L];
    uint16_t mid = (uint16_t)((uint32_t)prog_start + ((uint32_t)(prog_end - prog_start) * 8 / 10));
    uint32_t ctr = wots_grind(digest, N, hash_ctx, adrs, keypair, msg, sf, swn, cb, cb_ud, prog_start, mid);
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
        sha256_init_ctx(&ctx);
        sha256_copy_ctx(&ctx, hash_ctx);

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

uint32_t wots_pk_from_sig(const uint8_t* sig, const uint8_t* message, uint32_t message_len, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint32_t is_internal, uint32_t swn, uint8_t* out)
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
        sha256_init_ctx(&ctx);
        sha256_copy_ctx(&ctx, hash_ctx);

        setTypeAndClear(adrs, H_MSG_TYPE);
        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, r, R_LEN);
        sha256_add_to_ctx(&ctx, pk_root, N);
        sha256_add_to_ctx(&ctx, message, message_len);
        sha256_finalize(&ctx, digest);
    }

    uint8_t msg[L];
    uint32_t valid = wots_digest(digest, N, hash_ctx, ctr, adrs, keypair, msg, sf, swn);

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
    sha256_init_ctx(&ctx);
    sha256_copy_ctx(&ctx, hash_ctx);
    sha256_add_to_ctx(&ctx, adrs, 32);

    for(uint32_t i = 0; i < L; i++)
    {
        sha256_add_to_ctx(&ctx, pk[i], N);
    }

    sha256_finalize(&ctx, out);
    return 1;
}
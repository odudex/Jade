#ifndef XMSS_H
#define XMSS_H

#include "wots_c.h"

void xmss_treehash(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t target_height, uint32_t start_idx, uint8_t* out);

void xmss_root(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint8_t* out);

void xmss_auth_path(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint32_t idx, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end);

void xmss_pk_from_sig(const uint8_t* wots_sig, const uint8_t* auth, const uint8_t* message, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint32_t idx, uint32_t swn, uint8_t* out);

void xmss_sign(const uint8_t* message, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t h_prime, uint32_t idx, uint32_t swn, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end);

#endif
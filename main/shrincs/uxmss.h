#ifndef UXMSS_H
#define UXMSS_H

#include "wots_c.h"

void uxmss_treehash(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t start_level, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end);

void uxmss_root(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* out);

void uxmss_auth_path(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t q, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end);

void uxmss_pk_from_sig(const uint8_t* wots_sig, const uint8_t* auth, const uint8_t* message, uint32_t message_len, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t q, uint32_t swn, uint8_t* out);

void uxmss_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t q, uint32_t swn, uint8_t* out);

#endif
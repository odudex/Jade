#ifndef WOTS_C_H
#define WOTS_C_H

#include <stdint.h>

#include "address.h"
#include "constants.h"
#include "hash.h"

void base_w(const uint8_t* message, uint8_t* out_buffer);

void chain(const uint8_t* m, uint32_t start, uint32_t steps, SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* out);

void wots_pk_gen(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint8_t* out);
    
uint32_t wots_grind(const uint8_t* message, uint32_t message_len, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint8_t* msg_out, uint32_t sf, uint32_t swn, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end);

uint32_t wots_digest(const uint8_t* message, uint32_t message_len, SHA256_CTX* hash_ctx, uint32_t ctr, uint8_t* adrs, uint32_t keypair, uint8_t* msg_out, uint32_t sf, uint32_t swn);

void wots_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint32_t is_internal, uint32_t swn, uint8_t* out, shrincs_progress_cb cb, void *cb_ud, uint16_t prog_start, uint16_t prog_end);

uint32_t wots_pk_from_sig(const uint8_t* sig, const uint8_t* message, uint32_t message_len, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t keypair, uint32_t sf, uint32_t is_internal, uint32_t swn, uint8_t* out);

#endif
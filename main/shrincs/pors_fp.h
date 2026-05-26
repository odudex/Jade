#ifndef PORS_FP_H
#define PORS_FP_H

#include <math.h>
#include "address.h"
#include "constants.h"
#include "hash.h"

typedef struct {
    uint32_t a;
    uint32_t b;
} Tuple32_t;

typedef struct {
    uint32_t lvl;
    uint32_t idx;
    uint8_t val[N];
} PorsNode_t;

uint32_t extract_bits(const uint8_t* message, uint32_t start_bit_idx, uint32_t bits_amount);

uint32_t uint32_arr_have(uint32_t* arr, uint32_t arr_size, uint32_t elem);

void pors_msg_to_indices(const uint8_t* message, uint8_t* adrs, SHA256_CTX* hash_ctx, uint32_t* indices_out, uint8_t* xof_out);

uint32_t pors_octopus(uint32_t* indices, Tuple32_t* A_out, uint32_t* A_len_out);

void pors_grind(const uint8_t* message, uint32_t message_len, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, uint8_t* adrs, uint8_t* opt_rand, SHA256_CTX* hash_ctx, uint32_t* indices_out, uint8_t* digest_out, uint8_t* r_out);

void pors_sk_gen(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t leaf_idx, uint8_t* out);

void pors_treehash(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t target_height, uint32_t idx, uint8_t* out);

uint32_t pors_auth_path(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t* indices, uint32_t* A_len, uint8_t* out);

uint32_t pors_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* digest_out, uint8_t* out);

void pors_pk_from_sig(const uint8_t* sig, uint32_t indices[K], SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* out);

#endif
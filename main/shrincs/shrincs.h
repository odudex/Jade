#ifndef SHRINCS_H
#define SHRINCS_H

#include "random.h"
#include "uxmss.h"
#include "xmss.h"
#include "pors_fp.h"

typedef struct {
    uint8_t seed[N];
    uint8_t root[N];
} PublicKey;

typedef struct {
    uint8_t seed[N];
    uint8_t prf[N];
    uint8_t sf[N];
    uint8_t sl[N];
    PublicKey pk;
} SecretKey;

typedef struct {
    uint32_t q;
    uint32_t valid;
} State;

void generate_random_bytes(uint8_t* buffer, size_t length);

void parse_idx(const uint8_t* xof, uint32_t* idx_tree, uint32_t* idx_leaf);


void shrincs_key_gen(PublicKey* out_pk, SecretKey* out_sk, State* out_state);

// leaf_capture: optional buffer of (HSF+1)*N bytes - receives the stateful-tree
// leaves for later use as a signing cache (or NULL)
void shrincs_restore(const uint8_t* seed, PublicKey* out_pk, SecretKey* out_sk, State* out_state, uint8_t* leaf_capture);

// leaf_cache: optional cached stateful-tree leaves from shrincs_restore (or NULL)
uint32_t shrincs_sign_stateful(const uint8_t* message, uint32_t message_len, SecretKey* sk, State* state, uint32_t swn, uint8_t* out, shrincs_progress_cb cb, void *cb_userdata,
    const uint8_t* leaf_cache);

uint32_t shrincs_sign_stateless(const uint8_t* message, uint32_t message_len, SecretKey* sk, uint32_t swn, uint8_t* out, shrincs_progress_cb cb, void *cb_userdata);

uint32_t shrincs_verify_stateful(const uint8_t* message, uint32_t message_len, const uint8_t* sig, uint32_t sig_len, PublicKey* pk);

uint32_t shrincs_verify_stateless(const uint8_t* message, uint32_t message_len, const uint8_t* sig, PublicKey* pk);

uint32_t shrincs_verify(const uint8_t* message, uint32_t message_len, const uint8_t* sig, uint32_t sig_len, PublicKey* pk);

#endif
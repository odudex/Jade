#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "hash.h"
#include "hash_address.h"
#include "params.h"
#include "randombytes.h"
#include "wots.h"
#include "utils.h"
#include "xmss_commons.h"
#include "xmss_core.h"

/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of subtree_addr to be set.
 */
static void treehash(const xmss_params *params,
                     unsigned char *root, unsigned char *auth_path,
                     const unsigned char *sk_seed,
                     const unsigned char *pub_seed,
                     uint32_t leaf_idx, const uint32_t subtree_addr[8],
                     xmss_progress_cb cb, void *cb_userdata)
{
    unsigned char stack[(params->tree_height+1)*params->n];
    unsigned int heights[params->tree_height+1];
    unsigned int offset = 0;

    /* The subtree has at most 2^20 leafs, so uint32_t suffices. */
    uint32_t idx;
    uint32_t tree_idx;
    uint32_t total = (uint32_t)(1u << params->tree_height);

    /* We need all three types of addresses in parallel. */
    uint32_t ots_addr[8] = {0};
    uint32_t ltree_addr[8] = {0};
    uint32_t node_addr[8] = {0};

    /* Select the required subtree. */
    copy_subtree_addr(ots_addr, subtree_addr);
    copy_subtree_addr(ltree_addr, subtree_addr);
    copy_subtree_addr(node_addr, subtree_addr);

    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);
    set_type(ltree_addr, XMSS_ADDR_TYPE_LTREE);
    set_type(node_addr, XMSS_ADDR_TYPE_HASHTREE);

    for (idx = 0; idx < total; idx++) {
        if (cb && (idx % 100) == 0) {
            cb(idx, total, cb_userdata);
        }

        /* Add the next leaf node to the stack. */
        set_ltree_addr(ltree_addr, idx);
        set_ots_addr(ots_addr, idx);
        gen_leaf_wots(params, stack + offset*params->n,
                      sk_seed, pub_seed, ltree_addr, ots_addr);
        offset++;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if ((leaf_idx ^ 0x1) == idx) {
            memcpy(auth_path, stack + (offset - 1)*params->n, params->n);
        }

        /* While the top-most nodes are of equal height.. */
        while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) {
            /* Compute index of the new node, in the next layer. */
            tree_idx = (idx >> (heights[offset - 1] + 1));

            set_tree_height(node_addr, heights[offset - 1]);
            set_tree_index(node_addr, tree_idx);
            thash_h(params, stack + (offset-2)*params->n,
                           stack + (offset-2)*params->n, pub_seed, node_addr);
            offset--;
            heights[offset - 1]++;

            /* If this is a node we need for the auth path.. */
            if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) {
                memcpy(auth_path + heights[offset - 1]*params->n,
                       stack + (offset - 1)*params->n, params->n);
            }
        }
    }
    memcpy(root, stack, params->n);
}

/**
 * Given a set of parameters, this function returns the size of the secret key.
 * This is implementation specific, as varying choices in tree traversal will
 * result in varying requirements for state storage.
 */
unsigned long long xmss_xmssmt_core_sk_bytes(const xmss_params *params)
{
    return params->index_bytes + 4 * params->n;
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED], omitting algorithm OID.
 */
int xmss_core_keypair(const xmss_params *params,
                      unsigned char *pk, unsigned char *sk)
{
    /* The key generation procedure of XMSS and XMSSMT is exactly the same.
       The only important detail is that the right subtree must be selected;
       this requires us to correctly set the d=1 parameter for XMSS. */
    return xmssmt_core_keypair(params, pk, sk);
}

static int xmssmt_core_sign_cb(const xmss_params *params,
                               unsigned char *sk,
                               unsigned char *sm, unsigned long long *smlen,
                               const unsigned char *m, unsigned long long mlen,
                               xmss_progress_cb cb, void *cb_userdata);

/**
 * Signs a message. Returns an array containing the signature followed by the
 * message and an updated secret key.
 */
int xmss_core_sign(const xmss_params *params,
                   unsigned char *sk,
                   unsigned char *sm, unsigned long long *smlen,
                   const unsigned char *m, unsigned long long mlen,
                   xmss_progress_cb cb, void *cb_userdata)
{
    return xmssmt_core_sign_cb(params, sk, sm, smlen, m, mlen, cb, cb_userdata);
}

/*
 * Derives a XMSSMT key pair for a given parameter set.
 * Seed must be 3*n long.
 * Format sk: [(ceil(h/8) bit) index || SK_SEED || SK_PRF || root || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algorithm OID.
 */
int xmssmt_core_seed_keypair(const xmss_params *params,
                             unsigned char *pk, unsigned char *sk,
                             unsigned char *seed,
                             xmss_progress_cb cb, void *cb_userdata)
{
    unsigned char auth_path[params->tree_height * params->n];
    uint32_t top_tree_addr[8] = {0};
    set_layer_addr(top_tree_addr, params->d - 1);

    memset(sk, 0, params->index_bytes);
    sk += params->index_bytes;

    memcpy(sk, seed, 2 * params->n);

    memcpy(sk + 3 * params->n, seed + 2 * params->n,  params->n);
    memcpy(pk + params->n, sk + 3*params->n, params->n);

    treehash(params, pk, auth_path, sk, pk + params->n, 0, top_tree_addr,
             cb, cb_userdata);
    memcpy(sk + 2*params->n, pk, params->n);

    return 0;
}

int xmssmt_core_keypair(const xmss_params *params,
                        unsigned char *pk, unsigned char *sk)
{
    unsigned char seed[3 * params->n];

    xmss_randombytes(seed, 3 * params->n);
    return xmssmt_core_seed_keypair(params, pk, sk, seed, NULL, NULL);
}

static int xmssmt_core_sign_cb(const xmss_params *params,
                               unsigned char *sk,
                               unsigned char *sm, unsigned long long *smlen,
                               const unsigned char *m, unsigned long long mlen,
                               xmss_progress_cb cb, void *cb_userdata)
{
    const unsigned char *sk_seed = sk + params->index_bytes;
    const unsigned char *sk_prf = sk + params->index_bytes + params->n;
    const unsigned char *pub_root = sk + params->index_bytes + 2*params->n;
    const unsigned char *pub_seed = sk + params->index_bytes + 3*params->n;

    unsigned char root[params->n];
    unsigned char *mhash = root;
    unsigned long long idx;
    unsigned char idx_bytes_32[32];
    unsigned int i;
    uint32_t idx_leaf;

    uint32_t ots_addr[8] = {0};
    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    memcpy(sm + params->sig_bytes, m, mlen);
    *smlen = params->sig_bytes + mlen;

    idx = (unsigned long)bytes_to_ull(sk, params->index_bytes);

    if (idx >= ((1ULL << params->full_height) - 1)) {
        memset(sk, 0xFF, params->index_bytes);
        memset(sk + params->index_bytes, 0, (params->sk_bytes - params->index_bytes));
        if (idx > ((1ULL << params->full_height) - 1))
            return -2;
        if ((params->full_height == 64) && (idx == ((1ULL << params->full_height) - 1)))
            return -2;
    }

    memcpy(sm, sk, params->index_bytes);
    ull_to_bytes(sk, params->index_bytes, idx + 1);

    ull_to_bytes(idx_bytes_32, 32, idx);
    prf(params, sm + params->index_bytes, idx_bytes_32, sk_prf);

    hash_message(params, mhash, sm + params->index_bytes, pub_root, idx,
                 sm + params->sig_bytes - params->padding_len - 3*params->n,
                 mlen);
    sm += params->index_bytes + params->n;

    set_type(ots_addr, XMSS_ADDR_TYPE_OTS);

    for (i = 0; i < params->d; i++) {
        idx_leaf = (idx & ((1 << params->tree_height)-1));
        idx = idx >> params->tree_height;

        set_layer_addr(ots_addr, i);
        set_tree_addr(ots_addr, idx);
        set_ots_addr(ots_addr, idx_leaf);

        s_wots_sign(params, sm, root, sk_seed, pub_seed, ots_addr);
        sm += params->wots_sig_bytes;

        treehash(params, root, sm, sk_seed, pub_seed, idx_leaf, ots_addr,
                 cb, cb_userdata);
        sm += params->tree_height*params->n;
    }

    return 0;
}

int xmssmt_core_sign(const xmss_params *params,
                     unsigned char *sk,
                     unsigned char *sm, unsigned long long *smlen,
                     const unsigned char *m, unsigned long long mlen,
                     xmss_progress_cb cb, void *cb_userdata)
{
    return xmssmt_core_sign_cb(params, sk, sm, smlen, m, mlen, cb, cb_userdata);
}

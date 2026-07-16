#include <stdint.h>
#include <string.h>

#include "utils.h"
#include "hash.h"
#include "wots.h"
#include "hash_address.h"
#include "params.h"

/**
 * Helper method for pseudorandom key generation.
 * Expands an n-byte array into a len*n byte array using the `prf_keygen` function.
 */
static void expand_seed(const xmss_params *params,
                        unsigned char *outseeds, const unsigned char *inseed, 
                        const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;
    unsigned char buf[params->n + 32];

    set_hash_addr(addr, 0);
    set_key_and_mask(addr, 0);
    memcpy(buf, pub_seed, params->n);
    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        addr_to_bytes(buf + params->n, addr);
        prf_keygen(params, outseeds + i*params->n, buf, inseed);
    }
}

/**
 * Computes the chaining function.
 * out and in have to be n-byte arrays.
 *
 * Interprets in as start-th value of the chain.
 * addr has to contain the address of the chain.
 */
static void gen_chain(const xmss_params *params,
                      unsigned char *out, const unsigned char *in,
                      unsigned int start, unsigned int steps,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* Initialize out with the value at position 'start'. */
    memcpy(out, in, params->n);

    /* Iterate 'steps' calls to the hash function. */
    for (i = start; i < (start+steps) && i < params->wots_w; i++) {
        set_hash_addr(addr, i);
        thash_f(params, out, out, pub_seed, addr);
    }
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void xmss_base_w(const xmss_params *params,
                   int *output, const int out_len, const unsigned char *input)
{
    int in = 0;
    int out = 0;
    unsigned char total;
    int bits = 0;
    int consumed;

    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= params->wots_log_w;
        output[out] = (total >> bits) & (params->wots_w - 1);
        out++;
    }
}

/*
 * WOTS+C: derives the chain lengths for a message and a grinding counter and
 * returns the sum of the resulting base_w digits. The message digest is
 * H(msg || ctr), which yields exactly params->wots_len base_w digits.
 */
static unsigned int wots_lengths_from_ctr(const xmss_params *params,
                                          int *lengths,
                                          const unsigned char *msg, uint32_t ctr)
{
    unsigned char digest[params->n];
    unsigned int i, sum = 0;

    wots_c_hash(params, digest, msg, ctr);
    xmss_base_w(params, lengths, params->wots_len, digest);

    for (i = 0; i < params->wots_len; i++) {
        sum += lengths[i];
    }
    return sum;
}

/*
 * WOTS+C grinding: finds the smallest counter for which the base_w message
 * digits sum to the fixed target. The matching chain lengths are written to
 * 'lengths' and the counter is returned.
 */
static uint32_t xmss_wots_grind(const xmss_params *params, int *lengths,
                           const unsigned char *msg)
{
    uint32_t ctr;

    for (ctr = 0; ctr < UINT32_MAX; ctr++) {
        if (wots_lengths_from_ctr(params, lengths, msg, ctr)
                == params->wots_target_sum) {
            return ctr;
        }
    }
    return 0;
}

/**
 * WOTS key generation. Takes a 32 byte seed for the private key, expands it to
 * a full WOTS private key and computes the corresponding public key.
 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
 * and the address of this WOTS key pair.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pkgen(const xmss_params *params,
                unsigned char *pk, const unsigned char *seed,
                const unsigned char *pub_seed, uint32_t addr[8])
{
    uint32_t i;

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, pk, seed, pub_seed, addr);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i*params->n, pk + i*params->n,
                  0, params->wots_w - 1, pub_seed, addr);
    }
}

/**
 * Takes a n-byte message and the 32-byte seed for the private key to compute a
 * signature that is placed at 'sig'.
 */
void s_wots_sign(const xmss_params *params,
               unsigned char *sig, const unsigned char *msg,
               const unsigned char *seed, const unsigned char *pub_seed,
               uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;
    uint32_t ctr;
    /* The signature is laid out as [counter][chain_0]...[chain_{len-1}]. */
    unsigned char *chains = sig + XMSS_WOTS_CTR_BYTES;

    /* WOTS+C: grind a counter so the chain lengths sum to the fixed target,
       then store it (big-endian) at the front of the signature. */
    ctr = xmss_wots_grind(params, lengths, msg);
    ull_to_bytes(sig, XMSS_WOTS_CTR_BYTES, ctr);

    /* The WOTS+ private key is derived from the seed. */
    expand_seed(params, chains, seed, pub_seed, addr);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, chains + i*params->n, chains + i*params->n,
                  0, lengths[i], pub_seed, addr);
    }
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void s_wots_pk_from_sig(const xmss_params *params, unsigned char *pk,
                      const unsigned char *sig, const unsigned char *msg,
                      const unsigned char *pub_seed, uint32_t addr[8])
{
    int lengths[params->wots_len];
    uint32_t i;
    uint32_t ctr;
    const unsigned char *chains = sig + XMSS_WOTS_CTR_BYTES;

    /* WOTS+C: recover the grinding counter and recompute the chain lengths.
       A tampered counter simply yields a wrong public key, which is caught by
       the surrounding root comparison. */
    ctr = (uint32_t)bytes_to_ull(sig, XMSS_WOTS_CTR_BYTES);
    wots_lengths_from_ctr(params, lengths, msg, ctr);

    for (i = 0; i < params->wots_len; i++) {
        set_chain_addr(addr, i);
        gen_chain(params, pk + i*params->n, chains + i*params->n,
                  lengths[i], params->wots_w - 1 - lengths[i], pub_seed, addr);
    }
}

#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <stdint.h>

typedef void (*shrincs_progress_cb)(uint16_t value, void *userdata);

#if !defined(SHRINCS_B) && !defined(SHRINCS_L) && !defined(SHRINCS_B32)
    #define SHRINCS_L
#endif

#define N     ((uint32_t)16)                    // Security parameter (bytes)
#define R_LEN ((uint32_t)32)                    // Randomness length (bytes)

#if defined(SHRINCS_B)

#define W      ((uint32_t)256)                  // Winternitz parameter
#define L      ((uint32_t)16)                   // WOTS+C chain count
#define SWN    ((uint32_t)2040)                 // Target sum for WOTS+C
#define HSF    ((uint32_t)141)                  // Max stateful tree height
#define HSL    ((uint32_t)24)                   // Max stateless hypertree height
#define D      ((uint32_t)2)                    // Stateless hypertree layers
#define T      ((uint32_t)9245141)              // The number of secret values in PORS+FP tree
#define B      ((uint32_t)24)                   // PORS+FP tree height
#define K      ((uint32_t)6)                    // Number of PORS+FP revealed tree leafs
#define M_MAX  ((uint32_t)91)                   // Maximum size of the Octopus authentication path
#define margin ((uint32_t)7)

#elif defined(SHRINCS_B32)

#define W      ((uint32_t)256)
#define L      ((uint32_t)16)
#define SWN    ((uint32_t)2040)
#define HSF    ((uint32_t)210)
#define HSL    ((uint32_t)32)
#define D      ((uint32_t)4)
#define T      ((uint32_t)109571)
#define B      ((uint32_t)17)
#define K      ((uint32_t)11)
#define M_MAX  ((uint32_t)111)
#define margin ((uint32_t)10)

#else // SHRINCS_L

#define W      ((uint32_t)4)
#define L      ((uint32_t)64)
#define SWN    ((uint32_t)140)
#define HSF    ((uint32_t)189)
#define HSL    ((uint32_t)24)
#define D      ((uint32_t)2)
#define T      ((uint32_t)9245141)
#define B      ((uint32_t)24)
#define K      ((uint32_t)6)
#define M_MAX  ((uint32_t)91)
#define margin ((uint32_t)7)

#endif

#define H_PRIME       (HSL / D)
#define WOTS_SIGN_LEN (R_LEN + 4 + L * N)
#define XMSS_SIGN_LEN (WOTS_SIGN_LEN + H_PRIME * N)
#define PORS_SIGN_LEN (R_LEN + (K + M_MAX) * N)
#define MAX_SF_SIZE   (N + WOTS_SIGN_LEN + HSF * N)
#define SL_SIZE       (N + PORS_SIGN_LEN + XMSS_SIGN_LEN * D)

// PORS additional constants
#define c_shrincs       (256 / B)
#define xof_offset_bits ((((1 << B) * K + T - 1) / T + margin) * B + 16)
#define xof_block_idx   ((xof_offset_bits + 32 + 255) >> 8)

#define SF_WOTS_PK    ((uint32_t)0x01)
#define SF_WOTS_HASH  ((uint32_t)0x00)
#define SF_TREE       ((uint32_t)0x02)
#define SF_WOTS_GRIND ((uint32_t)0x03)
#define SF_H_MSG      ((uint32_t)0x04)
#define SF_WOTS_PRF   ((uint32_t)0x05)
#define PORS_HASH     ((uint32_t)0x06)
#define PORS_TREE     ((uint32_t)0x07)
#define PORS_PK       ((uint32_t)0x08)
#define PORS_PRF      ((uint32_t)0x09)
#define PORS_XOF      ((uint32_t)0x0A)
#define SL_WOTS_HASH  ((uint32_t)0x0B)
#define SL_WOTS_PK    ((uint32_t)0x0C)
#define SL_TREE       ((uint32_t)0x0D)
#define SL_WOTS_GRIND ((uint32_t)0x0E)
#define SL_H_MSG      ((uint32_t)0x0F)
#define SL_WOTS_PRF   ((uint32_t)0x10)
#define ROOT          ((uint32_t)0x11)

#endif // CONSTANTS_H
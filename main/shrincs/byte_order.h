#ifndef SHRINCS_BYTE_ORDER_H
#define SHRINCS_BYTE_ORDER_H
#include <stdint.h>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#endif
#ifndef BIG_ENDIAN
#define BIG_ENDIAN    __ORDER_BIG_ENDIAN__
#endif
#ifndef BYTE_ORDER
#define BYTE_ORDER    __BYTE_ORDER__
#endif

/* trezor-семантика: REVERSE32(in, out) == out = bswap(in) */
#define REVERSE32(w, x) ((x) = __builtin_bswap32((uint32_t)(w)))
#define REVERSE64(w, x) ((x) = __builtin_bswap64((uint64_t)(w)))

#endif
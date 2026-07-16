#include "randombytes.h"
#include "random.h"

void xmss_randombytes(unsigned char *x, unsigned long long xlen)
{
    get_random(x, (size_t)xlen);
}

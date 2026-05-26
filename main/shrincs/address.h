#ifndef ADDRESS_H
#define ADDRESS_H

#include <string.h>
#include <stdint.h>
#include "byte_order.h"

void setLayerAddress(uint8_t* adrs, uint32_t layer);
void setTreeAddress(uint8_t* adrs, uint32_t tree_addr1, uint64_t tree_addr2);
void setTypeAndClear(uint8_t* adrs, uint32_t type);
void setKeyPairAddress(uint8_t* adrs, uint32_t keypair);
void setChainAddress(uint8_t* adrs, uint32_t chain);
void setHashAddress(uint8_t* adrs, uint32_t hash);
void setTreeHeight(uint8_t* adrs, uint32_t height);
void setTreeIndex(uint8_t* adrs, uint32_t index);


#endif
#include "address.h"

void setLayerAddress(uint8_t* adrs, uint32_t layer) 
{
    REVERSE32(layer, layer);
    memcpy(adrs, &layer, sizeof(layer));
}

void setTreeAddress(uint8_t* adrs, uint32_t tree_addr1, uint64_t tree_addr2) 
{
    REVERSE32(tree_addr1, tree_addr1);
    REVERSE64(tree_addr2, tree_addr2);

    memcpy(adrs + 4, &tree_addr1, sizeof(tree_addr1));
    memcpy(adrs + 8, &tree_addr2, sizeof(tree_addr2));
}

void setTypeAndClear(uint8_t* adrs, uint32_t type) 
{
    REVERSE32(type, type);
    memcpy(adrs + 16, &type, sizeof(type));
    memset(adrs + 20, 0, 12);
}

void setKeyPairAddress(uint8_t* adrs, uint32_t keypair) 
{
    REVERSE32(keypair, keypair);
    memcpy(adrs + 20, &keypair, sizeof(keypair));
}

void setChainAddress(uint8_t* adrs, uint32_t chain) 
{
    REVERSE32(chain, chain);
    memcpy(adrs + 24, &chain, sizeof(chain));
}

void setHashAddress(uint8_t* adrs, uint32_t hash) 
{
    REVERSE32(hash, hash);
    memcpy(adrs + 28, &hash, sizeof(hash));
}

void setTreeHeight(uint8_t* adrs, uint32_t height) 
{
    REVERSE32(height, height);
    memcpy(adrs + 24, &height, sizeof(height));
}

void setTreeIndex(uint8_t* adrs, uint32_t index) 
{
    REVERSE32(index, index);
    memcpy(adrs + 28, &index, sizeof(index));
}
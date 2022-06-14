//
// Created by benlar on 1/4/22.
//

#ifndef DAA_BRIDGE_V2_HASH_H
#define DAA_BRIDGE_V2_HASH_H
#include "stddef.h"
#include "stdint.h"

void hash_begin(uint16_t alg);
void hash_update(uint8_t* data, size_t len);
void hash_final(uint8_t* bufferOut);

#endif //DAA_BRIDGE_V2_HASH_H

//
// Created by benlar on 1/4/22.
//

#ifndef DAA_BRIDGE_V2_PERSISTENCE_H
#define DAA_BRIDGE_V2_PERSISTENCE_H
#include "stdint.h"
#include "stddef.h"
#include "defines.h"

KEY request_key(uint16_t id);
void request_manifest_digest(uint8_t* result);
#endif //DAA_BRIDGE_V2_PERSISTENCE_H

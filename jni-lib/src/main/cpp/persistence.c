//
// Created by benlar on 1/4/22.
//

// Temporary solution
#include <stdlib.h>
#include "persistence.h"
#include "defines.h"
#include "memory.h"
#include "hash.h"

KEY issuer_pk;
KEY daa_key;
KEY endorsement_key;
KEY wallet_key;




KEY request_key(uint16_t id) {
    switch (id) {
        case ISSUER_KEY:
            return issuer_pk;
            break;
        case DAA_KEY:
            return daa_key;
            break;
        case WALLET_KEY:
            return wallet_key;
            break;
        case ENDORSEMENT_KEY:
            return endorsement_key;
            break;
        default:
            exit(INVALID_KEY_ID);

    }
}

void request_manifest_digest(uint8_t *result) {
    // Just for testing
    memset(result,0,DIGEST_SIZE);
    hash_begin(HASH_ALG);
    hash_update(result,DIGEST_SIZE);
    hash_update(result,DIGEST_SIZE);
    hash_update(result,DIGEST_SIZE);
    hash_final(result);
}



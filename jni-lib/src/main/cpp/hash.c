//
// Created by benlar on 1/4/22.
//
#include <stdio.h>
#include <stdlib.h>
#include "hash.h"
#include "openssl/sha.h"
#include "ibmtss/TPM_Types.h"
#include "defines.h"

SHA256_CTX sha256;

void hash_begin(uint16_t alg) {
    if (alg == TPM_ALG_SHA256) {
        SHA256_Init(&sha256);
    } else {
        printf("[-] Hash algorithm unsupported\n");
        exit(HASH_UNSUPPORTED);
    }

}

void hash_update(uint8_t *data, size_t len) {
    SHA256_Update(&sha256, data, len); // Message Digest
}

void hash_final(uint8_t *bufferOut) {
    SHA256_Final(bufferOut, &sha256);
}

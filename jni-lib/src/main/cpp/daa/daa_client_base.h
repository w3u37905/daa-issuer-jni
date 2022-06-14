//
// Created by benlar on 12/30/21.
//

#ifndef DAA_DAA_CLIENT_BASE_H
#define DAA_DAA_CLIENT_BASE_H

#include <stdint.h>
#include <stddef.h>
#include "defines.h"


DAA_CONTEXT * new_daa_context();
void free_daa_context(DAA_CONTEXT* ctx);

/* Join Operations */
DAA_RC daa_prepare_host_str(DAA_CONTEXT* ctx, ECC_POINT* daa_pub, ECC_POINT* commit_data, uint8_t* credential_key, uint8_t* ek_pub, uint8_t* bufferOut);    // Tested OK
DAA_RC daa_finalize_credential_signature(DAA_CONTEXT* ctx, DAA_SIGNATURE* signature, uint8_t* host_str_digest);
DAA_RC daa_decrypt_credential_data(DAA_CONTEXT* ctx, uint8_t* encrypted_credential, int32_t len, uint8_t* credential_key, DAA_CREDENTIAL* credOut); //TODO: Do we know the length of the encrypted credential?

/* Sign Operations */
DAA_CREDENTIAL daa_prepare_commit(DAA_CONTEXT* ctx, DAA_CREDENTIAL credential, COMMIT_INFORMATION* info); // Seriously can't be wrong
DAA_RC daa_prepare_hash(DAA_CONTEXT* ctx, uint8_t* message, size_t len, DAA_CREDENTIAL* randomized_credential, COMMIT_RESPONSE* tpm_commit_data, uint8_t* toHashOut);
DAA_RC daa_finalize_signature(DAA_CONTEXT* ctx, DAA_SIGNATURE* signature, uint8_t* hashedData);

/* Verify Operations */
DAA_RC daa_verify_signature(DAA_CONTEXT* ctx, uint8_t* message, size_t len, DAA_SIGNATURE* signature); // Tested OK

#endif //DAA_DAA_CLIENT_BASE_H

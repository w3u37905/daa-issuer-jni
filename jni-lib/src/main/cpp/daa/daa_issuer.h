//
// Created by benlar on 12/30/21.
//

#ifndef DAA_DAA_ISSUER_H
#define DAA_DAA_ISSUER_H

#include <stdint.h>
#include <stddef.h>
#include "defines.h"


CHALLENGE_CREDENTIAL daa_initiate_join(DAA_CONTEXT *ctx, ECC_POINT *daa_pub, uint8_t* daa_tpm_name, uint8_t *ek_pub);
FULL_CREDENTIAL daa_on_host_response(DAA_CONTEXT *ctx, uint8_t *credentialKey, DAA_SIGNATURE *sig, int8_t newSignature);

#endif //DAA_DAA_ISSUER_H

//
// Created by benlar on 1/7/22.
//
#ifdef __cplusplus
extern "C" {
#endif

#ifndef DAA_BRIDGE_V2_ISSUER_INTERFACE_H
#define DAA_BRIDGE_V2_ISSUER_INTERFACE_H

#include "../defines.h"

char* send_issuer_registration(const char* json);
void onNewSessionFromVCIssuer(TPM2B_PUBLIC *EK, uint8_t* signedNonce, int nonceLen);
char* send_challenge_response(const char* cr);






#endif //DAA_BRIDGE_V2_ISSUER_INTERFACE_H
#ifdef __cplusplus
}
#endif

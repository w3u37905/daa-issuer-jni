//
// Created by benlar on 1/4/22.
//
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include "ibmtss/TPM_Types.h"
#ifndef DAA_BRIDGE_V2_DAA_BRIDGE_H
#define DAA_BRIDGE_V2_DAA_BRIDGE_H
#include "defines.h"
TPMT_PUBLIC onCreateAttestationKeyCommand(TPM2B_PUBLIC* issuer_pub, uint8_t* signedNonce, int nonceLen);
CHALLENGE_RESPONSE onIssuerChallenge(CHALLENGE_CREDENTIAL challenge, AUTHORIZATION signAuth, AUTHORIZATION commit_auth, TPML_PCR_SELECTION pcr);
void requestNonce(TPM2B_NONCE* nonceOut);
void writeWalletKey(uint8_t* key, int keyLen);
void writeIssuerKey(uint8_t *key, int keyLen);
void writeIssuerPrivKey(uint8_t *key, int keyLen);
void writeWalletPrivKey(uint8_t *key, int keyLen);
void onIssuerFCRE(FULL_CREDENTIAL fcre);


DAA_SIGNATURE execute_daa_sign(uint8_t* msg, size_t msgLen, uint8_t* signed_nonce, size_t signed_nonce_len);
TPM2B_PUBLIC setup();
int verifyDAASignature(uint8_t* message, size_t len, DAA_SIGNATURE* signature);
#endif //DAA_BRIDGE_V2_DAA_BRIDGE_H


uint8_t credentialDigest[32];
// DataVaults


#define MAX_TPM_KEY_LEN 512

// pseudonym structure, might be changed depending on the serialization
typedef struct {
    uint8_t keyBuffer [MAX_TPM_KEY_LEN];
    uint16_t keyLen;
    size_t uuid;
    uint8_t properties; // TBD (e.g. bit 1 set = unlinkable, bit 2 set = ecc key....
} PSEUDONYM;


// Setup the system with the Issuers Public Key - return 0 on success, -1 otherwise
// PEM Format is prefered
int setupDAA(uint8_t* issuerPk, uint8_t pkLen);

// Here we work under the assumption that this code will handle communicate with the issuer
// Creates DAA Key and retrieves credential
// Can take a policy (e.g. PCR Values for use of pseudonym / Keys) can also be null and we'll go for a default
// 0 on success -1 otherwise
int initiateJoinPhase(uint8_t* policy);

// creates a pseudonym
PSEUDONYM createPseudonym(uint8_t properties);

// Sign data: Will probably create a structure for this, but this should work as a start.
void daaSign(uint8_t* data, size_t dataLen, PSEUDONYM* pseudonym, uint8_t* bufferOut, size_t* sizeOut);
void writeWalletKey(uint8_t *key, int keyLen);
#ifdef __cplusplus
}
#endif

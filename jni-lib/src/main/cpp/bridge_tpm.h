//
// Created by benlar on 1/4/22.
//
#ifdef __cplusplus
extern "C" {
#endif
#ifndef DAA_BRIDGE_V2_BRIDGE_TPM_H
#define DAA_BRIDGE_V2_BRIDGE_TPM_H

#include <string.h>
#include "ibmtss/tss.h"
#include "ibmtss/tssresponsecode.h"
#include "ibmtss/tssutils.h"
#include "ibmtss/tssmarshal.h"
#include "ibmtss/TPM_Types.h"
#include "ibmtss/Unmarshal_fp.h"
#include "ibmtss/tsscrypto.h"
#include "ibmtss/tsscryptoh.h"
#include "ibmtss/tsstransmit.h"
#include "daa/defines.h"
#include "defines.h"


#define NOT_CRITICAL 0
#define CRITICAL 1

uint8_t tpm2_startAuthSession(TPMI_SH_POLICY sessionType, TPM_HANDLE *handleOut, TPM2B_NONCE *tpmNonce);

SIGNATURE_VERIFICATION tpm2_verifySignature(TPM_HANDLE key_handle, uint8_t* expected, int mdlen, uint8_t* sig, int siglen);

uint8_t tpm2_flushContext(TPM_HANDLE handle);

uint8_t tpm2_create(TPM2B_PUBLIC *Keytemplate, TPM_HANDLE parent, TPML_PCR_SELECTION *pcrSelection,
                    const TPM_HANDLE *session, TPM_KEY *keyOut);

uint8_t tpm2_createPrimary(TPM2B_PUBLIC *keytemplate, TPMI_RH_HIERARCHY hierarchy, PRIMARY_KEY *primaryKey);

uint8_t tpm2_createLoaded(TPM2B_PUBLIC *keytemplate, TPM_HANDLE parent, TPM_HANDLE *handleOut);

uint8_t tpm2_policyCommandCode(TPM_HANDLE session, TPM_CC commandCode);

uint8_t tpm2_policyAuthorize(TPM_HANDLE session, TPMT_TK_VERIFIED* ticket, TPM2B_NAME* signingName, TPM2B_DIGEST* expected);

uint8_t tpm2_load(TPM_KEY *key, TPM_HANDLE parent, LOADED_KEY *outLoaded);

uint8_t tpm2_sign(TPM_HANDLE loadedKey, const TPM_HANDLE *session, TPMT_SIG_SCHEME *scheme, TPM_HASH *hash,
                  TPMT_SIGNATURE *signature);

uint8_t tpm2_hash(TPM2B_MAX_BUFFER *buffer, TPM_HANDLE hierarchy, TPM_HASH *hashOut);

uint8_t tpm2_commit(TPM_HANDLE key, TPM2B_ECC_POINT *point, TPM_HANDLE session, TPM2B_SENSITIVE_DATA *secret, TPM2B_ECC_PARAMETER *param,
                    COMMIT_DATA *commitData);

        uint8_t tpm2_certifyCreation(TPM_HANDLE key, TPM_KEY* keyInfo, TPM_HANDLE signingHandle, TPMT_SIG_SCHEME* signScheme, CREATION_CERT *cert);
uint8_t tpm2_certify(TPM_HANDLE keyToCertify, TPM_HANDLE signingHandle, TPMT_SIG_SCHEME* sigScheme, KEY_CERT* certOut);
uint8_t
tpm2_activateCredential(TPM_HANDLE activateHandle, TPM_HANDLE keyHandle, CHALLENGE_CREDENTIAL *cred, unsigned char *certBuffer, int* certLen);

LoadExternal_Out tpm2_loadExternal(TPM2B_PUBLIC *publicKey, TPMI_RH_HIERARCHY hierarchy, TPM_HANDLE* loadOut);

uint8_t tpm2_evictControl(TPM_HANDLE handle, TPM_HANDLE persistentHandle);

uint8_t legacy_tpm2_sign(TPM_HANDLE key, uint8_t *message, uint16_t len, TPM_HANDLE *policySession, TPMT_SIGNATURE* sigOut);

// Helper
uint8_t tpm2_getPolicyDigest(TPM_HANDLE session, uint8_t* bufferOut);

uint8_t tpm2_GetRandom(uint8_t noBytes, uint8_t* buff);

// Policies
uint8_t tpm2_policySigned(TPM_HANDLE publicKey, TPMI_SH_POLICY session, TPMT_SIGNATURE *signature, TPM2B_NONCE* nonce);
uint8_t tpm2_policyPCR(TPM_HANDLE session, TPML_PCR_SELECTION* pcrSelection);
int8_t initializeTPM(int reboot);

void finalizeContext();
#endif //DAA_BRIDGE_V2_BRIDGE_TPM_H
#ifdef __cplusplus
}
#endif
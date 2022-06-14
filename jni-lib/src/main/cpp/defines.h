//
// Created by benlar on 1/4/22.
//

#ifndef DAA_BRIDGE_V2_DEFINES_H
#define DAA_BRIDGE_V2_DEFINES_H

#define ID_LEN 4
#define ISSUER_PK_MAX_LEN 512
#define HASH_ALG 0x000B // SHA256
#define EK_SCHEME TPM_ALG_RSASSA
#define CC_LEN 4
#define EK_PERSISTENT_HANDLE 0x81000000 // not right?
#define NAME_LEN 34


// Key IDs live in 0x100x area
#define ISSUER_KEY 0x1001
#define WALLET_KEY 0x1002
#define DAA_KEY 0x1003
#define ENDORSEMENT_KEY 0x1004


#define REBOOT 1
#define NO_REBOOT 0

#include "daa/defines.h"
#include "ibmtss/TPM_Types.h"
#include "ibmtss/tss.h"

typedef Create_Out TPM_KEY;
typedef CreatePrimary_Out PRIMARY_KEY;
typedef Load_Out LOADED_KEY;
typedef Hash_Out TPM_HASH;
typedef Commit_Out COMMIT_DATA;
typedef Certify_Out KEY_CERT;
typedef CertifyCreation_Out CREATION_CERT;
typedef VerifySignature_Out SIGNATURE_VERIFICATION;
typedef struct{
    ECC_POINT point;
} ECC_PUBLIC_KEY;

typedef struct{
    uint8_t key[ISSUER_PK_MAX_LEN];
    uint16_t len;
} RSA_PUBLIC_KEY;

typedef union{
    ECC_PUBLIC_KEY eccKey;
    RSA_PUBLIC_KEY rsaKey;
} CRYPT_KEY;

typedef struct{
    CRYPT_KEY cryptKey;
    uint8_t name[NAME_LEN];
} KEY;


typedef struct {
    TPMT_PUBLIC akPub;
    TPM2B_PUBLIC ekPub;
} DOOR_ISSUER_REGISTRATION;




// Error codes
#define HASH_UNSUPPORTED 1
#define INVALID_KEY_ID 2
#define NV_ERROR 3
#define DIGEST_SIZE 32


typedef struct{
    size_t sigLen;
    uint8_t signature[150];
    uint8_t digest[DIGEST_SIZE];
    uint8_t approvedPolicy[DIGEST_SIZE];
} AUTHORIZATION;
#endif //DAA_BRIDGE_V2_DEFINES_H

//
// Created by benlar on 12/30/21.
//
#include "stddef.h"
#include "stdint.h"
#ifndef DAA_DEFINES_H
#define DAA_DEFINES_H

typedef uint8_t DAA_RC;

#define EC_POINT_MAX_LEN 128
#define EC_SIGNATURE_MAX_LEN 128
#define MAX_DIGEST_LEN 64
#define MAX_SYM_LEN 256
#define MAX_STR_LEN 2048
#define MAX_JOIN_CRED_LENGTH 1024
#define MAX_SECRET_LENGTH 1024
#define CVM_SIZE 18


/* Return Codes */
#define RC_OK 0
#define RC_UNSPECIFIED_FAILURE 1
#define CREDENTIAL_DECRYPTION_ERROR 2
#define RC_BAD_SIGNATURE 3
#define RC_BAD_CREDENTIAL_P1 4;
#define RC_BAD_CREDENTIAL_P2 5;

typedef struct {
    uint8_t x_coord[EC_POINT_MAX_LEN];
    uint8_t y_coord[EC_POINT_MAX_LEN];
    uint8_t coord_len;
} ECC_POINT;



typedef struct {
    uint8_t credential[MAX_JOIN_CRED_LENGTH];
    uint8_t secret[MAX_SECRET_LENGTH];

    int credential_length;
    int secret_length;

} CHALLENGE_CREDENTIAL;


typedef struct {
    ECC_POINT points[4];
} DAA_CREDENTIAL;

typedef struct {
    uint8_t signatureR[EC_SIGNATURE_MAX_LEN];
    uint8_t signatureS[EC_SIGNATURE_MAX_LEN];
    uint8_t V[MAX_DIGEST_LEN];
    DAA_CREDENTIAL rcre;
} DAA_SIGNATURE;


typedef struct{
    unsigned char credneitalKey[32];
    int certLen;
    DAA_SIGNATURE sig;
} CHALLENGE_RESPONSE;

typedef struct {
    CHALLENGE_CREDENTIAL join_credential;
    uint8_t credentialEncrypted[MAX_JOIN_CRED_LENGTH]; // TODO: Right size
    int encryptedLength;
} FULL_CREDENTIAL;

typedef struct {
    uint16_t halg;
    uint8_t halg_size;
    uint8_t ecc_point_len;
    uint16_t iss_pk_len;
    uint16_t ek_pk_len;
    uint8_t name_len;
    uint8_t symmetric_key_bytes;
    uint8_t BNP256_ORDER[32];


    unsigned char bnp256_gX[1]; // Generator X
    unsigned char bnp256_gY[1]; // Generator Y
    int signature_len;
} DAA_CONTEXT;

typedef struct {
    ECC_POINT p1;
    uint8_t secret[MAX_SYM_LEN];
    uint8_t parameter[EC_POINT_MAX_LEN];

    size_t secretLen;
    size_t parameterLen;
} COMMIT_INFORMATION;

typedef struct {
    ECC_POINT K;
    ECC_POINT L;
    ECC_POINT E;
    uint16_t counter;
} COMMIT_RESPONSE;


#endif //DAA_DEFINES_H

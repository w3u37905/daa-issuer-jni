//
// Created by benlar on 12/30/21.
//
#include <memory.h>
#include <openssl/sha.h>
#include <unistd.h>
#include "daa_client_base.h"
#include "openssl/bn.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "BN_Crypto.h"
#include "openssl/rand.h"
#include "issPk.h"
#include "daa_pairings.h"



/*
 * Function:  concat_data
 * --------------------
 *  Creates C_String a hashes it as H(Message_Digest || R || S || T || W || J || K || L || E)
 *
 *  daa_ctx:        DAA Context
 *  rcre:           The randomized credential
 *  msgDigest:      The message digest
 *  E_prime:        Calculated E_Prime
 *  bufferOut:      The output buffer
 *
 */
// TODO: Support multiple algorithms
// TODO: Mix with get_c_str as they are doing the same
void concat_data(DAA_CONTEXT *ctx, DAA_CREDENTIAL *rcre, uint8_t *msgDigest, size_t len, EC_POINT *E_prime,
                 uint8_t *bufferOut) {
    // As we're note using basename, we don't care about point J, K and L_prime, but should be implemented

    uint8_t E_x[ctx->ecc_point_len];
    uint8_t E_y[ctx->ecc_point_len];
    uint8_t J[2 * ctx->ecc_point_len];
    uint8_t K[2 * ctx->ecc_point_len];
    uint8_t L[2 * ctx->ecc_point_len];

    memset(J, 0, 2 * ctx->ecc_point_len);
    memset(K, 0, 2 * ctx->ecc_point_len);
    memset(L, 0, 2 * ctx->ecc_point_len);


    getBinaryCoordinates(E_prime, E_x, E_y);


    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msgDigest, len); // Message Digest
    SHA256_Update(&sha256, rcre->points[0].x_coord, ctx->halg_size); // Rx
    SHA256_Update(&sha256, rcre->points[0].y_coord, ctx->halg_size); // Ry

    SHA256_Update(&sha256, rcre->points[1].x_coord, ctx->halg_size); // Sx
    SHA256_Update(&sha256, rcre->points[1].y_coord, ctx->halg_size); // Sy


    SHA256_Update(&sha256, rcre->points[2].x_coord, ctx->halg_size); // Tx
    SHA256_Update(&sha256, rcre->points[2].y_coord, ctx->halg_size); // Ty

    SHA256_Update(&sha256, rcre->points[3].x_coord, ctx->halg_size); // Wx
    SHA256_Update(&sha256, rcre->points[3].y_coord, ctx->halg_size); // Wy

    SHA256_Update(&sha256, J, 2 * ctx->ecc_point_len); // J(XY)
    SHA256_Update(&sha256, K, 2 * ctx->ecc_point_len); // K(XY)
    SHA256_Update(&sha256, L, 2 * ctx->ecc_point_len); // L(XY)


    SHA256_Update(&sha256, E_x, ctx->ecc_point_len); // E'x
    SHA256_Update(&sha256, E_y, ctx->ecc_point_len); // E'y


    SHA256_Final(bufferOut, &sha256);

}

/*
 * Function:  get_c_str
 * --------------------
 *  Creates C_String a hashes it as H(Message_Digest || R || S || T || W || J || K || L || E)
 *
 *  daa_ctx:        DAA Context
 *  daaCredentials: The randomized credential
 *  cd:             The Commit Response from the TPM containing K,L and E
 *  J:              The J point in case of basename
 *  msgDigest:      The message digest
 *  bufferOut:      The output buffer
 *
 */
// TODO: Support multiple algorithms
void get_c_str(DAA_CONTEXT *ctx, DAA_CREDENTIAL *daaCredentials, COMMIT_RESPONSE *cd, ECC_POINT *J, uint8_t *msgDigest,
               uint8_t *bufferOut) {
    SHA256_CTX sha256;
    uint8_t null_buffer[2 * ctx->ecc_point_len];
    memset(null_buffer, 0, 2 * ctx->ecc_point_len);


    SHA256_Init(&sha256);
    SHA256_Update(&sha256, msgDigest, ctx->halg_size); // Message Digest

    SHA256_Update(&sha256, daaCredentials->points[0].x_coord, ctx->ecc_point_len); // Rx
    SHA256_Update(&sha256, daaCredentials->points[0].y_coord, ctx->ecc_point_len); // Ry

    SHA256_Update(&sha256, daaCredentials->points[1].x_coord, ctx->ecc_point_len); // Sx
    SHA256_Update(&sha256, daaCredentials->points[1].y_coord, ctx->ecc_point_len); // Sy

    SHA256_Update(&sha256, daaCredentials->points[2].x_coord, ctx->ecc_point_len); // Tx
    SHA256_Update(&sha256, daaCredentials->points[2].y_coord, ctx->ecc_point_len); // Ty

    SHA256_Update(&sha256, daaCredentials->points[3].x_coord, ctx->ecc_point_len); // Wx
    SHA256_Update(&sha256, daaCredentials->points[3].y_coord, ctx->ecc_point_len); // Wy

    // As we're currently not using a Base name J,is nothing, so we exclude this
    //TODO: Implement
    if (J == NULL) {
        SHA256_Update(&sha256, null_buffer, 2 * ctx->ecc_point_len);
    } else {
        SHA256_Update(&sha256, J->x_coord, ctx->halg_size);
        SHA256_Update(&sha256, J->y_coord, ctx->halg_size);

    }

    if (cd->K.coord_len > 0) {
        SHA256_Update(&sha256, cd->K.x_coord, cd->K.coord_len); // Kx
        SHA256_Update(&sha256, cd->K.y_coord, cd->K.coord_len); // Ky
    } else {
        SHA256_Update(&sha256, null_buffer, 2 * ctx->ecc_point_len);
    }
    if (cd->L.coord_len > 0) {
        SHA256_Update(&sha256, cd->L.x_coord, cd->L.coord_len); // Kx
        SHA256_Update(&sha256, cd->L.y_coord, cd->L.coord_len); // Ky
    } else {
        SHA256_Update(&sha256, null_buffer, 2 * ctx->ecc_point_len);
    }
    if (cd->E.coord_len > 0) {
        SHA256_Update(&sha256, cd->E.x_coord, cd->E.coord_len); // Kx
        SHA256_Update(&sha256, cd->E.y_coord, cd->E.coord_len); // Ky
    } else {
        SHA256_Update(&sha256, null_buffer, 2 * ctx->ecc_point_len);
    }


    SHA256_Final(bufferOut, &sha256);
}


/*
 * Function:  randomizeCredential
 * --------------------
 *  Randomizes credential provided as per specification
 *
 *  daa_ctx:        DAA Context
 *  credential:     Credential to randomize
 *
 *  returns: 0 on success, otherwise 1
 */
uint8_t randomizeCredential(DAA_CONTEXT *daa_ctx, DAA_CREDENTIAL *credential) {
    uint8_t randomBytes[32];

    // Start by getting random bytes, the size of a component
    // TODO: handle multiple algorithms
    RAND_bytes(randomBytes, 32);

    BIGNUM *resPtr = BN_Mod(randomBytes, daa_ctx->BNP256_ORDER);

    if (resPtr == NULL) {
        printf("[-] Pointer error\n");
        return EXIT_FAILURE;
    }

    // Now we get our generator for curve for BNP 256 ( i think )
    EC_GROUP *ecgp = get_ec_group_bnp256(); // @ 4
    if (ecgp == NULL) {
        BN_free(resPtr);
        printf("[-] Error in getting EC Group\n");
        return EXIT_FAILURE;

    }

    // We do the multiplication on each point
    for (int p = 0; p < 4; p++) {
        EC_POINT *resultingPoint = EC_POINT_new(ecgp);
        EC_Point_Multiplication(resPtr, credential->points[p].x_coord, credential->points[p].y_coord, resultingPoint);
        EC_POINT_free(resultingPoint);
    }

    BN_free(resPtr);
    EC_GROUP_free(ecgp); // @ 4
    return EXIT_SUCCESS;

}


/*
 * Function:  aesDecrypt
 * --------------------
 *  Decrypts data using AES 128 CTR
 *
 *  encryptedData:  The encrypted data to decrypt
 *  key:            AES Key to use
 *  len:            Length of the ciphertext
 *  finalBuffer:    Buffer to hold the resulting decrypted data
 *
 *  returns: 0 on success, otherwise 1
 */
uint8_t aesDecrypt(uint8_t *encryptedData, uint8_t *key, int len, uint8_t *finalBuffer) {
    EVP_CIPHER_CTX *ctx;
    uint8_t iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);
    size_t blockLen = (len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
    uint8_t creBuffer[blockLen * AES_BLOCK_SIZE]; //TODO: Couldn't we just take the known size + nearest block?
    int outLen;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        printf("[-] Error in decryption ctx\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_get_cipherbyname("AES-128-CTR"), NULL, key, iv)) {
        printf("[-] Error in decryption init\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;

    }

    if (1 != EVP_DecryptUpdate(ctx, creBuffer, &outLen, encryptedData, len)) {
        printf("[-] Error in decryption update\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;

    }

    int plaintext_len = outLen;

    if (1 != EVP_DecryptFinal_ex(ctx, &creBuffer[outLen], &outLen)) {
        printf("[-] Error in decryption fianl\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;

    }
    plaintext_len += outLen;

    EVP_CIPHER_CTX_free(ctx);

    memcpy(finalBuffer, &creBuffer, plaintext_len);
    return EXIT_SUCCESS;
}

/*
 * Function:  daa_prepare_host_str
 * --------------------
 *  Computes the host string to be hashed and signed by the TPM
 *      computes as: host_str = H(P_1 || Qs || X || Y || K_1 || Ek || E)
 *
 *  ctx: The DAA Context
 *  daa_pub:        The DAA Public EC Point
 *  commit_data:    Commit Data from the Commit Operation
 *  credential_key: The credential key from the Issuer
 *  ek_pub:         The public RSA key from the Endorsement Key
 *  bufferOut:      Buffer to hold the resulting host string (Size of the cipher)
 *
 *  returns: 0 on success, otherwise error code
 */
//TODO: Reduce operations
DAA_RC daa_prepare_host_str(DAA_CONTEXT *ctx, ECC_POINT *daa_pub, ECC_POINT *commit_data, uint8_t *credential_key,
                            uint8_t *ek_pub, uint8_t *bufferOut) {
    uint8_t P1[2 * ctx->ecc_point_len];
    uint8_t DAA[2 * ctx->ecc_point_len];
    uint8_t E[2 * ctx->ecc_point_len];
    uint8_t host_str[ctx->iss_pk_len + ctx->ek_pk_len + ctx->symmetric_key_bytes];
    uint8_t p_str[MAX_STR_LEN];

    memset(P1, 0, 2 * ctx->ecc_point_len);
    // Build P1
    P1[2 * ctx->ecc_point_len / 2 - 1] = ctx->bnp256_gX[0];
    P1[2 * ctx->ecc_point_len - 1] = ctx->bnp256_gY[0];

    //  Daa public keys
    memcpy(DAA, daa_pub->x_coord, daa_pub->coord_len);
    memcpy(&DAA[2 * ctx->ecc_point_len / 2], &daa_pub->y_coord[0], daa_pub->coord_len * sizeof(uint8_t));

    // E point from commit data
    memcpy(E, commit_data->x_coord, commit_data->coord_len);
    memcpy(&E[2 * ctx->ecc_point_len / 2], &commit_data->y_coord[0], commit_data->coord_len * sizeof(uint8_t));

    // The last thing is the host str = {iss_public x,y, new credentialKey and endorsementKeyPub}
    memcpy(host_str, issPk, ctx->iss_pk_len);

    //NOTE: Changed size to AES128 bytes instead for Issuer PK Len ( not true?? )
    memcpy(&host_str[ctx->iss_pk_len], credential_key, ctx->symmetric_key_bytes * sizeof(uint8_t));

    memcpy(&host_str[ctx->iss_pk_len + ctx->symmetric_key_bytes], ek_pub,
           ctx->ek_pk_len * sizeof(uint8_t));


    // Now we can concat all of this into the final
    memcpy(p_str, P1, 2 * ctx->ecc_point_len);
    memcpy(&p_str[1 * 2 * ctx->ecc_point_len], DAA, 2 * ctx->ecc_point_len * sizeof(uint8_t));
    memcpy(&p_str[2 * 2 * ctx->ecc_point_len], E, 2 * ctx->ecc_point_len * sizeof(uint8_t));
    memcpy(&p_str[3 * 2 * ctx->ecc_point_len], host_str,
           (ctx->iss_pk_len + ctx->ek_pk_len + ctx->symmetric_key_bytes) * sizeof(uint8_t));


    // Then we hash the result
    // TODO: Support multiple hash algorithms
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, p_str,
                  (3 * 2 * ctx->ecc_point_len) + (ctx->iss_pk_len + ctx->ek_pk_len + ctx->symmetric_key_bytes));
    SHA256_Final(bufferOut, &sha256);


    return RC_OK;
}

/*
 * Function:  finalize_credential_signature
 * --------------------
 *  Computes number as H(K || H(host_str)) and calculate it mod BNP256 ORDER
 *
 *  ctx:                The DAA Context
 *  signature:          The signature containing K (SignatureR)
 *  host_str_digest:    The digest from the TPM Hash Operation
 *  bufferOut:          The output buffer for the modulus operation (same size as input)
 *
 *  returns: 0 on success, otherwise error code
 */
DAA_RC daa_finalize_credential_signature(DAA_CONTEXT *ctx, DAA_SIGNATURE *signature, uint8_t *host_str_digest) {
    BIGNUM *resPtr = NULL;
    SHA256_CTX sha256;
    uint8_t num[ctx->halg_size];

    // Prepare num
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, signature->signatureR, ctx->signature_len);
    SHA256_Update(&sha256, host_str_digest, ctx->halg_size);
    SHA256_Final(num, &sha256);

    // Modulus
    resPtr = BN_Mod(num, ctx->BNP256_ORDER);

    // Convert it to binary
    BN_bn2bin(resPtr, signature->V);

    // Free resPtr
    BN_free(resPtr);

    return RC_OK;

}

/*
 * Function:  daa_decrypt_credential_data
 * --------------------
 *  Decrypts the credential data from the full credential received by the Issuer
 *  after getting the credential key from activate credentail
 *
 *  ctx:                    The DAA Context
 *  encrypted_credential:   The encrypted credential
 *  len:                    The size of the encrypted credential // TODO: Do we need?
 *  credential_key          The credential key from activate credential
 *  credOut                 Output buffer of type DAA_CREDENTIAL to hold the decrypted credential
 *
 *  returns: 0 on success, otherwise error code
 */
// TODO: Handle multiple sizes and algorithms
DAA_RC daa_decrypt_credential_data(DAA_CONTEXT *ctx, uint8_t *encrypted_credential, int32_t len, uint8_t *credential_key,
                                   DAA_CREDENTIAL *credOut) {

    uint8_t credential[len];

    // Then we decrypt the credentials
    uint8_t rc = aesDecrypt(encrypted_credential, credential_key, len, credential);
    if (rc != EXIT_SUCCESS) {
        return CREDENTIAL_DECRYPTION_ERROR;
    }

    // Now we deserialize the data, and add it to our credential
    memcpy(credOut->points[0].x_coord, &credential[ctx->ecc_point_len * 0], ctx->ecc_point_len);
    memcpy(credOut->points[0].y_coord, &credential[ctx->ecc_point_len * 1], ctx->ecc_point_len);
    credOut->points[0].coord_len = ctx->ecc_point_len;

    memcpy(credOut->points[1].x_coord, &credential[ctx->ecc_point_len * 2], ctx->ecc_point_len);
    memcpy(credOut->points[1].y_coord, &credential[ctx->ecc_point_len * 3], ctx->ecc_point_len);
    credOut->points[1].coord_len = ctx->ecc_point_len;

    memcpy(credOut->points[2].x_coord, &credential[ctx->ecc_point_len * 4], ctx->ecc_point_len);
    memcpy(credOut->points[2].y_coord, &credential[ctx->ecc_point_len * 5], ctx->ecc_point_len);
    credOut->points[2].coord_len = ctx->ecc_point_len;

    memcpy(credOut->points[3].x_coord, &credential[ctx->ecc_point_len * 6], ctx->ecc_point_len);
    memcpy(credOut->points[3].y_coord, &credential[ctx->ecc_point_len * 7], ctx->ecc_point_len);
    credOut->points[3].coord_len = ctx->ecc_point_len;

    return RC_OK;
}

/*
 * Function:  daa_prepare_commit
 * --------------------
 *  Randomized the credential and prepares the data to be used in commit.
 *
 *  ctx:                    The DAA Context
 *  credential:             The (copy) of the credential
 *  info                    Output buffer of type COMMIT_INFORMATION holding data to be used
 *
 *  returns: 0 on success, otherwise error code
 */
//TODO: Implement basename
DAA_CREDENTIAL daa_prepare_commit(DAA_CONTEXT *ctx, DAA_CREDENTIAL credential, COMMIT_INFORMATION *info) {

    // Randomize Credential
    uint8_t rc = randomizeCredential(ctx, &credential);
    if (rc != EXIT_SUCCESS) {
        printf("[-] Error in randomizing credential\n");
        exit(22);
    }

    // We'll now take our 2nd point (S := Randomized B) and put it in the structure
    memcpy(info->p1.x_coord, credential.points[1].x_coord, ctx->ecc_point_len);
    memcpy(info->p1.y_coord, credential.points[1].y_coord, ctx->ecc_point_len);
    info->p1.coord_len = ctx->ecc_point_len;

    // If we don't use basename, our commit data and secret are empty.
    info->secretLen = 0;
    info->parameterLen = 0;

    return credential;
}

/*
 * Function:  daa_prepare_hash
 * --------------------
 *  Prepares the message to be hashed before signing.
 *  Computed as H(Message_Digest || R || S || T || W || J || K || L || E)
 *
 *  ctx:                    The DAA Context
 *  message:                The message that is to be hashed and signed
 *  len:                    Length of the message
 *  randomized_credential:  The randomized credential to use
 *  tpm_commit_data:        Commit Data returned from the TPM
 *  hashOut:                Output buffer to hold the digest to be hashed
 *
 *  returns: 0 on success, otherwise error code
 */
DAA_RC daa_prepare_hash(DAA_CONTEXT *ctx, uint8_t *message, size_t len, DAA_CREDENTIAL *randomized_credential,
                        COMMIT_RESPONSE *tpm_commit_data, uint8_t *toHashOut) {
    uint8_t message_digest[ctx->halg_size];

    // Begin by hashing the message
    // TODO: Support multiple
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, len);
    SHA256_Final(message_digest, &sha256);

    // Then we can calculate the final digest
    get_c_str(ctx, randomized_credential, tpm_commit_data, NULL, message_digest, toHashOut);

    return RC_OK;

}

/*
 * Function:  daa_finalize_signature
 * --------------------
 *  Finalizes the DAA Signature to be ready for verification, by adding data to V in signature
 *
 *  ctx:                    The DAA Context
 *  signature:              Signature from TPM
 *  hashedData:             THe digest that was signed
 *
 *  returns: 0 on success, otherwise error code
 */
DAA_RC daa_finalize_signature(DAA_CONTEXT *ctx, DAA_SIGNATURE *signature, uint8_t *hashedData) {
    uint8_t num[ctx->halg_size];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, signature->signatureR, ctx->signature_len);
    SHA256_Update(&sha256, hashedData, ctx->halg_size);
    SHA256_Final(num, &sha256);

    BIGNUM *bPtr = BN_Mod(num, ctx->BNP256_ORDER);

    BN_bn2bin(bPtr, signature->V);
    BN_free(bPtr);

    return RC_OK;
}


/*
 * Function:  daa_verify_signature
 * --------------------
 *  Verifies a DAA signature
 *
 *  ctx:                    The DAA Context
 *  message:                The received message
 *  len:                    The length of the message
 *  signature:              The DAA Signature
 *  credential:             The credential from the signer
 *
 *  returns: 0 on success, otherwise error code
 */
DAA_RC daa_verify_signature(DAA_CONTEXT *ctx, uint8_t *message, size_t len, DAA_SIGNATURE *signature) {
    clock_t t;
    t = clock();


    uint8_t msgDigest[ctx->halg_size];
    uint8_t c_str[ctx->halg_size];
    uint8_t h2_temp[ctx->halg_size];
    uint8_t h2_ref[ctx->halg_size];
    DAA_RC rc = RC_UNSPECIFIED_FAILURE;

    // Step 1) Calculate the digest
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message, len);
    SHA256_Final(msgDigest, &sha256);

    // TODO: Find out how to make OpenSSL to not fuck with our arrays
    DAA_CREDENTIAL rcre;
    for (int i = 0; i < 4; i++) {
        memcpy(rcre.points[i].x_coord, signature->rcre.points[i].x_coord, signature->rcre.points->coord_len);
        memcpy(rcre.points[i].y_coord, signature->rcre.points[i].y_coord, signature->rcre.points->coord_len);
        rcre.points[i].coord_len = signature->rcre.points->coord_len;
    }

    // TODO: Implement basename
    // TODO: Do we need to test pairings?

    // Step 2) Do math
    // Sig 0 = K = SigR
    // Sig 1 = W = SigS
    // Sig 2 = V

    EC_GROUP *ecgp = get_ec_group_bnp256();     // @2

    EC_POINT *s_pt = EC_POINT_new(ecgp);
    EC_POINT *h2_pt = EC_POINT_new(ecgp); // @3
    EC_POINT *e_prime_pt = EC_POINT_new(ecgp); // @3

    BIGNUM *s_bn = BN_new();                    // @4
    BIGNUM *h2_bn = BN_new();                   // @5
    BIGNUM *h2_prime;                           // @5

    BN_bin2bn(signature->signatureS, 32, s_bn);
    BN_bin2bn(signature->V, ctx->ecc_point_len, h2_bn);
    // Add

    EC_Point_Multiplication(s_bn, rcre.points[1].x_coord, rcre.points[1].y_coord, s_pt);
    EC_Point_Multiplication(h2_bn, rcre.points[3].x_coord, rcre.points[3].y_coord, h2_pt);

    // Invert
    EC_Point_inverse(h2_pt);


    EC_Add_Points(s_pt, h2_pt, e_prime_pt);

    // Now we do our C_sign
    concat_data(ctx, &signature->rcre, msgDigest, ctx->halg_size, e_prime_pt, c_str);

    // TODO: Again, why the double hash
    uint8_t doublehash_c[ctx->halg_size];
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, c_str, ctx->halg_size);
    SHA256_Final(doublehash_c, &sha256);

    // We can now build our comparison value
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, signature->signatureR, ctx->signature_len);
    SHA256_Update(&sha256, doublehash_c, ctx->halg_size);
    SHA256_Final(h2_temp, &sha256);

    // Then we calculate the prime
    h2_prime = BN_Mod(h2_temp, ctx->BNP256_ORDER); //TODO: Are we sure we don't lose our prime?
    BN_bn2bin(h2_prime, h2_ref);

    // Now compare
    if (memcmp(h2_ref, signature->V, ctx->halg_size) == 0) {
        rc = RC_OK;
    } else rc = RC_BAD_SIGNATURE;
    // Cleanup
    EC_GROUP_free(ecgp);
    BN_free(s_bn);
    BN_free(h2_bn);
    BN_free(h2_prime);
    EC_POINT_free(s_pt);
    EC_POINT_free(h2_pt);
    EC_POINT_free(e_prime_pt);
    if (rc != RC_OK)
        return rc;
    else if(verify_credential(ctx, &signature->rcre) == RC_OK){
        return RC_OK;
    }
    return RC_UNSPECIFIED_FAILURE;

}

/*
 * Function:  new_daa_context
 * --------------------
 *  Creates a new DAA Context with standard parameters
 *
 *  returns: pointer to DAA Context
 */
DAA_CONTEXT *new_daa_context() {
    DAA_CONTEXT *ctx = malloc(sizeof(DAA_CONTEXT));
    uint8_t BNP256_ORDER[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD, 0x46, 0xE5, 0xF2, 0x5E, 0xEE,
                                      0x71,
                                      0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53,
                                      0x6C,
                                      0xD1, 0x0B, 0x50, 0x0D};
    ctx->ecc_point_len = 32;
    ctx->halg_size = 32;
    ctx->iss_pk_len = 256;
    ctx->symmetric_key_bytes = 16;
    memcpy(ctx->BNP256_ORDER, BNP256_ORDER, 32);
    ctx->signature_len = 32;
    ctx->ek_pk_len = 256;
    ctx->name_len = 34;
    ctx->bnp256_gX[0] = 0x01;
    ctx->bnp256_gY[0] = 0x02;

    return ctx;
}

/*
 * Function:  free_daa_context
 * --------------------
 *  Deletes DAA Context
 *
 *  returns: nothing
 */
void free_daa_context(DAA_CONTEXT *ctx) {
    free(ctx);
}

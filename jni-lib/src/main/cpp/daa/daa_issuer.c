//
// Created by benlar on 12/30/21.
//
#include <openssl/rand.h>
#include <stdio.h>
#include <memory.h>
#include "daa_issuer.h"
#include "openssl/hmac.h"
#include <math.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include "openssl/rsa.h"
#include "issPk.h"
#include "BN_Crypto.h"
#define  LOG_TAG    "DAA-BRIDGE"

#define  LOGD(...) DEBUG_PRINT(__VA_ARGS__)
#define  LOGE(...) DEBUG_PRINT(__VA_ARGS__)


ECC_POINT daa_stored;
uint8_t ek_stored[1024];
uint8_t daa_name[NAME_MAX];


uint8_t credentialKey_local[MAX_SYM_LEN];


// Yeah this should not be like this
// TODO: move to file
uint8_t sk_x[32] = {0x65, 0xA9, 0xBF, 0x91, 0xAC, 0x88, 0x32, 0x37, 0x9F, 0xF0, 0x4D, 0xD2, 0xC6, 0xDE, 0xF1,
                    0x6D, 0x48, 0xA5, 0x6B, 0xE2, 0x44, 0xF6, 0xE1, 0x92, 0x74, 0xE9, 0x78, 0x81, 0xA7, 0x76,
                    0x54, 0x3C};
uint8_t sk_y[32] = {0x12, 0x6F, 0x74, 0x25, 0x8B, 0xB0, 0xCE, 0xCA, 0x2A, 0xE7, 0x52, 0x2C, 0x51, 0x82, 0x5F,
                    0x98, 0x05, 0x49, 0xEC, 0x1E, 0xF2, 0x4F, 0x81, 0xD1, 0x89, 0xD1, 0x7E, 0x38, 0xF1, 0x77,
                    0x3B, 0x56};
uint8_t identity[9] = {"IDENTITY\0"};
uint8_t storage[8] = {"STORAGE\0"};
uint8_t integrity[10] = {"INTEGRITY\0"};


uint8_t encryptAES(DAA_CONTEXT *daaContext, uint8_t *data, int dataLen, uint8_t *key, uint16_t blocksize, char *cipoher,
                   uint8_t *out) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    uint8_t iv[blocksize];
    memset(iv, 0, blocksize);
    size_t enc_blocks = 1 + dataLen / daaContext->symmetric_key_bytes;

    uint8_t tempBuffer[
            enc_blocks *
            daaContext->symmetric_key_bytes]; // We use the TMP_BUFFER so we don't get any potential padding

    int num = 0;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_get_cipherbyname(cipoher), NULL, key, iv)) {
        LOGD("[-] Error in Init Ecnryption in openSSL\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }

    if (1 != EVP_EncryptUpdate(ctx, &tempBuffer[0], &num, &data[0], dataLen)) {
        LOGD("[-] Error in EncryptUpdate in openSSL\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    int ciphertext_len = num;

    if (1 != EVP_EncryptFinal_ex(ctx, &tempBuffer[num], &num)) {
        LOGD("[-] Error in EncryptFinal in openSSL\n");
        EVP_CIPHER_CTX_free(ctx);
        return EXIT_FAILURE;
    }
    ciphertext_len += num;


    memcpy(out, tempBuffer, ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return EXIT_SUCCESS;

}

void HMAC_SHA256(uint8_t *data, int dataLen, uint8_t *key, int keyLen, uint8_t *result) {

    HMAC_CTX *ctx = HMAC_CTX_new(); // @1
    unsigned int len = 32; // The length of the sha256 hash

    HMAC_CTX_reset(ctx);


    // Using sha256 hash engine here.
    HMAC_Init_ex(ctx, &key[0], keyLen, EVP_sha256(), NULL);
    HMAC_Update(ctx, &data[0], dataLen);
    HMAC_Final(ctx, &result[0], &len);

    HMAC_CTX_free(ctx); // @!
}

void tempNIST(uint8_t *key, int keysize, uint8_t *input, int inputsize, int key_size_in_bits,
              uint8_t *resultFINAL) {
    uint32_t cnt = 1;
    size_t size_in_bytes = (key_size_in_bits + 7) / 8;
    size_t n_hashes = ceil((double) key_size_in_bits / 256.00);

    uint8_t finalDigest[size_in_bytes * n_hashes];

    // Let's do this
    for (int i = 0; i < n_hashes; i++) {
        // Begin by converting the count to 4 bytes
        uint8_t binaryCount[4];
        binaryCount[0] = (cnt >> 24) & 0xFF;
        binaryCount[1] = (cnt >> 16) & 0xFF;
        binaryCount[2] = (cnt >> 8) & 0xFF;
        binaryCount[3] = cnt & 0xFF;

        // Now we're gonna prepare a buffer for input to hmac
        uint8_t inputBuff[inputsize + 4]; // We add fixed data and out count.
        memcpy(inputBuff, binaryCount, 4);
        memcpy(&inputBuff[4], input, inputsize * sizeof(uint8_t));


        // Now HMAC
        uint8_t resultBuff[size_in_bytes];
        HMAC_SHA256(inputBuff, inputsize + 4, key, keysize, resultBuff);

        // Copy to result
        memcpy(&finalDigest[(cnt - 1) * size_in_bytes], resultBuff, size_in_bytes * sizeof(uint8_t));

        cnt++;

    }

    //TODO: It makes NO sense that we do this so many times, when we only take part of it ...
    memcpy(resultFINAL, finalDigest, size_in_bytes);
}


uint8_t
KDFa_SHA256(uint8_t *seedKey, int seedKeySize, uint8_t *label, int labelSize, uint8_t *contextU,
            int contextUSize, uint8_t *contextV, int contextVSize, int sizeInBits,
            uint8_t *finalResult) {

    int fixedDataLen = labelSize + contextUSize + contextVSize + 4;
    uint8_t fixedData[fixedDataLen];
    uint8_t size_bin[4];

    // Convert the sizeInBits to binary
    uint32_t ival = sizeInBits;
    for (int i = 0; i < 4; ++i) {
        size_bin[3 - i] = ival & 0xff;
        ival >>= 8;
    }

    // Now add the fixed data
    memcpy(fixedData, label, labelSize);
    memcpy(&fixedData[labelSize], &contextU[0], contextUSize * sizeof(uint8_t));
    memcpy(&fixedData[labelSize + contextUSize], &contextV[0], contextVSize * sizeof(uint8_t));
    memcpy(&fixedData[labelSize + contextUSize + contextVSize], &size_bin[0], 4 * sizeof(uint8_t));

    tempNIST(seedKey, seedKeySize, fixedData, fixedDataLen, sizeInBits, finalResult);
}

/*
 * Function:  RSAEncrypt
 * --------------------
 *  Encrypts data using RSA
 *
 *  label:          Parameter
 *  labelSize:      Size of parameter
 *  in:             Data to encrypt
 *  inSize:         Data length
 *  mod:            Modulus for RSA
 *  modLen:         Length od modulus
 *  exponent:       Exponent for RSA
 *  exponentLen:    Length of exponent
 *  outBuffer:      Buffer for holding encrypted data
 *  goingOut:       Pointer to variable where number of bytes written are noted
 *
 *
 *  returns: 0 if success, Return Code otherwise.
 */
uint8_t
RSAEncrypt(uint8_t *label, int labelSize, uint8_t *in, int inSize, uint8_t *mod, int modLen,
           uint8_t *exponent, int exponentLen, uint8_t *outBufferc, int *goingOut) {
    // Begin by converting the values
    BIGNUM *modBN = BN_new();                    // @ 1
    BIGNUM *expBN = BN_new();                    // @ 2

    BN_bin2bn(mod, modLen, modBN);
    BN_bin2bn(exponent, exponentLen, expBN);

    // Define RSA
    RSA *rsa_key = RSA_new();


    if (rsa_key != NULL) {
        RSA_set0_key(rsa_key, modBN, expBN, NULL);
    } else {
        LOGD("[-] Noble able to set RSA key\n");
        BN_free(modBN);
        BN_free(expBN);
        RSA_free(rsa_key);
        return EXIT_FAILURE;
    }

    // Define our buffers
    int outlen = RSA_size(rsa_key);
    uint8_t padded[outlen];




    // Manually do the padding to select the hash functions, SHA256 is used for both OAEP and MGF1 //Chris Newton
    if (RSA_padding_add_PKCS1_OAEP_mgf1(padded, outlen, in, inSize, label, labelSize, EVP_sha256(),
                                        EVP_sha256()) <= 0) {
        LOGD("[-] Padding failed\n ");
        BN_free(modBN);
        BN_free(expBN);
        RSA_free(rsa_key);

        return EXIT_FAILURE;

    }

    // Now encrypt
    size_t ct_size = RSA_public_encrypt(outlen, padded, outBufferc, rsa_key, RSA_NO_PADDING);
    if (ct_size != outlen) {
        LOGD("[-] Error in encryption, key length (%zu) vs cipher text (%d)? \n", ct_size, outlen);
        BN_free(modBN);
        BN_free(expBN);
        RSA_free(rsa_key);
        return EXIT_FAILURE;

    }

    *goingOut = outlen;

    // Cleanup
    RSA_free(rsa_key);
    // BN_free(modBN);
    // BN_free(expBN);
    //   RSA_free(rsa_key); //TODO: SIGSEV

    return EXIT_SUCCESS;
}

/*
 * Function:  make_credential_data
 * --------------------
 *  Generates the challenge credential, which the client should activate
 *
 *  daa_ctx                 The DAA Context
 *
 *  returns: the Challenge Credential
 */
CHALLENGE_CREDENTIAL make_credential_data(DAA_CONTEXT *daa_ctx) {
    CHALLENGE_CREDENTIAL cred;
    int rc;
    int outLen;
    unsigned int len = daa_ctx->halg_size;
    uint8_t seed[daa_ctx->halg_size];
    uint8_t aes_key[daa_ctx->symmetric_key_bytes];
    uint8_t HMAC_Key[daa_ctx->halg_size];
    uint8_t toEncrypt[CVM_SIZE]; // Credential key + size
    uint8_t null[0];
    uint8_t c_hat[CVM_SIZE];


    // We begin by making a Credential Key Key
    // NOTE: For testing purposes it can take a CK
    RAND_bytes(credentialKey_local, daa_ctx->symmetric_key_bytes);

    // Then our seed, again with test parameters possible
    RAND_bytes(seed, daa_ctx->halg_size);

    // Then we begin to create our secret. Our exponent is a standard 3.
    uint8_t exponent[3] = {0x01, 0x00, 0x01};


    // Encrypt secret with RSA
    rc = RSAEncrypt(identity, 9, seed, daa_ctx->halg_size, ek_stored,
                    daa_ctx->ek_pk_len, exponent, 3, cred.secret, &outLen);

    // Check for errors
    if (rc == EXIT_FAILURE) {
        LOGD("[-] Unable to encrypt secret\n");
        exit(-1);
    }


    // AES Key
    KDFa_SHA256(seed, daa_ctx->halg_size, storage, 8, daa_name, daa_ctx->name_len, null, 0, 128, aes_key);

    // HMAC key
    KDFa_SHA256(seed, daa_ctx->halg_size, integrity, 10, null, 0, null, 0, 256, HMAC_Key);


    // NOw to build credential

    // Set size (16) //TODO: Why? We know the size, of course if we want to change it later on... Maybe not hardcode
    toEncrypt[0] = 0x00;
    toEncrypt[1] = 0x10;

    // Copy our credentialKey_local into the buffer
    memcpy(&toEncrypt[2], credentialKey_local, 16);

    // Encrypt it with the generated AES Key
    encryptAES(daa_ctx, toEncrypt, 18, aes_key, daa_ctx->symmetric_key_bytes, "AES-128-CFB", c_hat);

    // We now create our C_BLOB

    // The first two characters states how long the digest is (32)
    cred.credential[0] = 0x00;
    cred.credential[1] = 0x20;


    // We then prepare the digest
    HMAC_CTX *ctx = HMAC_CTX_new(); // @1
    HMAC_CTX_reset(ctx);


    HMAC_Init_ex(ctx, HMAC_Key, daa_ctx->halg_size, EVP_sha256(), NULL);
    HMAC_Update(ctx, c_hat, CVM_SIZE);                  // Add c_hat
    HMAC_Update(ctx, daa_name, daa_ctx->name_len);   // Add DAA Name

    HMAC_Final(ctx, &cred.credential[2], &len);                  // Finalize and put after our size parameter

    HMAC_CTX_free(ctx); // @1

    // Then we add the C_HAt afterward
    memcpy(&cred.credential[daa_ctx->halg_size + 2], c_hat, 18);


    // NOw we finalize the credential
    cred.credential_length = daa_ctx->halg_size + 2 + 18;
    cred.secret_length = 256; // TODO: common

    return cred;

}

/*
 * Function:  recalculate_host_string
 * --------------------
 *  Recalculates the host_string and
 *
 *  daaContext              The DAA Context
 *  ekPub:                  The public part of the Endorsement Key (local ref)
 *  ck:                     The credential key (local ref)
 *  bufferOut:              The output buffer for the calculated string
 *
 *  returns: Nothing
 */
void recalculate_host_string(DAA_CONTEXT *ctx, uint8_t *ekPub, uint8_t *ck,
                             uint8_t *bufferOut) {
    memcpy(bufferOut, issPk, ctx->iss_pk_len);

    //NOTE: Changed size to AES128 bytes instead for Issuer PK Len ( not true?? )
    memcpy(&bufferOut[ctx->iss_pk_len], ck, ctx->symmetric_key_bytes * sizeof(uint8_t));

    memcpy(&bufferOut[ctx->iss_pk_len + ctx->symmetric_key_bytes], ekPub,
           ctx->ek_pk_len * sizeof(uint8_t));

}

/*
 * Function:  issuer_verify_signature
 * --------------------
 *  Verifies a DAA Signature from a client to the Issuer.
 *  Will recalculate host_str and verify
 *
 *  daaContext              The DAA Context
 *  sig:                    The signature to verify
 *  newSignature:           1 if yes, 0 otherwise
 *  host_str:               The host generated string
 *
 *  returns: Nothing
 */
int issuer_verify_signature(DAA_CONTEXT *daaContext, DAA_SIGNATURE *sig, int newSignature, uint8_t *host_str) {


    // Now we verify the signature
    BN_CTX *ctx = BN_CTX_new(); // @1
    EC_GROUP *ecgrp = get_ec_group_bnp256();    // @2
    EC_POINT *w_P1 = EC_POINT_new(ecgrp); // @3
    BIGNUM *v_prime = NULL;

    // get W_p1
    // Testet OK / BL
    EC_Generator_Multiplication(sig->signatureS, daaContext->signature_len,
                                w_P1);

    // get V_q2
    EC_POINT *v_q2 = EC_POINT_new(ecgrp);   // @4

    BIGNUM *bn_V = BN_new();     // @5
    BN_bin2bn(sig->V, daaContext->halg_size, bn_V);


    uint8_t tempX[32];
    uint8_t tempY[32];
    memcpy(tempX, daa_stored.x_coord, daa_stored.coord_len);
    memcpy(tempY, daa_stored.y_coord, daa_stored.coord_len);

    EC_Point_Multiplication(bn_V, tempX, tempY, v_q2);

    // get U' by inverting and adding
    // Tester OK / BL
    EC_Point_inverse(v_q2);

    // Add w_p1 and the now inverted v_q2
    EC_POINT *u_mark = EC_POINT_new(ecgrp); // 6
    EC_Add_Points(w_P1, v_q2, u_mark);


    // 	Byte_buffer pp=sha256_bb(g1_point_concat(p1)+g1_point_concat(daa_public_key)+g1_point_concat(u_prime_bb)+str);
    // Get the binary coordinates
    uint8_t x_u_mark[daaContext->ecc_point_len];
    uint8_t y_u_mark[daaContext->ecc_point_len];

    getBinaryCoordinates(u_mark, x_u_mark, y_u_mark);

    // Time to hash
    uint8_t PP[daaContext->halg_size];
    uint8_t PP_TPM[daaContext->halg_size];

    // We need to pad gX and gY to the left
    uint8_t P1_x[daaContext->ecc_point_len];
    uint8_t P1_y[daaContext->ecc_point_len];
    memset(P1_x, 0, daaContext->ecc_point_len);
    memset(P1_y, 0, daaContext->ecc_point_len);
    P1_y[daaContext->ecc_point_len - 1] = daaContext->bnp256_gY[0];
    P1_x[daaContext->ecc_point_len - 1] = daaContext->bnp256_gX[0];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, P1_x, daaContext->ecc_point_len);
    SHA256_Update(&sha256, P1_y, daaContext->ecc_point_len);
    SHA256_Update(&sha256, daa_stored.x_coord, daa_stored.coord_len);
    SHA256_Update(&sha256, daa_stored.y_coord, daa_stored.coord_len);
    SHA256_Update(&sha256, x_u_mark, daaContext->ecc_point_len);
    SHA256_Update(&sha256, y_u_mark, daaContext->ecc_point_len);
    SHA256_Update(&sha256, host_str, 528);
    SHA256_Final(PP, &sha256);



    // Double Hash
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, PP, daaContext->halg_size);
    SHA256_Final(PP_TPM, &sha256);

    // Calculate V_Prime
    if (newSignature == 0) {
        v_prime = BN_Mod(PP_TPM, daaContext->BNP256_ORDER); // Maybe use own order?
    } else {
        uint8_t tmp[daaContext->halg_size];
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, sig->signatureR, daaContext->signature_len);
        SHA256_Update(&sha256, PP_TPM, daaContext->halg_size);
        SHA256_Final(tmp, &sha256);

        v_prime = BN_Mod(tmp, daaContext->BNP256_ORDER);
    }

    // COnvert to comparable data
    uint8_t v_prime_buff[daaContext->ecc_point_len];
    BN_bn2bin(v_prime, v_prime_buff);


    if (memcmp(sig->V, v_prime_buff, 32) == 0) {
#ifdef VERBOSE
        LOGD("[+] DAA Signature verified by Issuer\n");
#endif
    } else {
        LOGD("[-] DAA Signature failed to verify by Issuer\n");
        BN_free(bn_V); // @5
        BN_free(v_prime); // @7
        EC_POINT_free(w_P1); // @3
        EC_POINT_free(v_q2); // @4
        EC_POINT_free(u_mark); //@6
        EC_GROUP_free(ecgrp); // @2
        BN_CTX_free(ctx); // @1
        return EXIT_FAILURE;
    }

    BN_free(bn_V); // @5
    BN_free(v_prime); // @7
    EC_POINT_free(w_P1); // @3
    EC_POINT_free(v_q2); // @4
    EC_POINT_free(u_mark); //@6
    EC_GROUP_free(ecgrp); // @2
    BN_CTX_free(ctx); // @1

    return EXIT_SUCCESS;
}


/*
 * Function:  make_daa_credential
 * --------------------
 *  Builds the final DAA Credential
 *
 *  daaCtx                  The DAA Context
 *  daaKeyIn:               The ECC point for the public DAA Key
 *  credentialBuffer:       The output buffer for the credential (Should hold 4 points (8 coordinates))
 *
 *
 *  returns: Nothing
 */
void make_daa_credential(DAA_CONTEXT *daaCtx, ECC_POINT *daaKeyIn, uint8_t *credentialBuffer) {


#ifdef VERBOSE
    LOGD("[*] Issuer building DAA Credential\n");
#endif
    // We prepare random bytes.
    uint8_t r[daaKeyIn->coord_len];
    RAND_bytes(r, daaKeyIn->coord_len);

    // Now we prepare to do the math
    EC_GROUP *ecgrp = get_ec_group_bnp256();  // @2

    // We then define our Big Numbers
    BIGNUM *sk_x_bn = BN_new();
    BIGNUM *sk_y_bn = BN_new();
    BIGNUM *order_bn = BN_new();
    BIGNUM *r_bn = BN_new();
    BIGNUM *ry_bn = BN_new();
    BIGNUM *daa_x_bn = BN_new();
    BIGNUM *daa_y_bn = BN_new();


    // We define our Points
    EC_POINT *pt_qs = EC_POINT_new(ecgrp);
    EC_POINT *pt_a = EC_POINT_new(ecgrp);
    EC_POINT *pt_b = EC_POINT_new(ecgrp);
    EC_POINT *pt_c = EC_POINT_new(ecgrp);
    EC_POINT *pt_d = EC_POINT_new(ecgrp);
    EC_POINT *pt_tmp = EC_POINT_new(ecgrp);

    // Assign values
    BN_bin2bn(sk_x, daaCtx->ecc_point_len, sk_x_bn);
    BN_bin2bn(sk_y, daaCtx->ecc_point_len, sk_y_bn);
    BN_bin2bn(daaCtx->BNP256_ORDER, daaCtx->ecc_point_len, order_bn);
    BN_bin2bn(r, daaKeyIn->coord_len, r_bn);

    // We then assign our public key from DAA
    BN_CTX *ctx = BN_CTX_new(); // @1
    BN_bin2bn(daaKeyIn->x_coord, daaKeyIn->coord_len, daa_x_bn);
    BN_bin2bn(daaKeyIn->y_coord, daaKeyIn->coord_len, daa_y_bn);

    EC_POINT_set_affine_coordinates_GFp(ecgrp, pt_qs, daa_x_bn, daa_y_bn, ctx);
    BN_CTX_free(ctx); // TODO: Seriously necessary?

    // Now we can generate our points //TODO: Cleanup and put in header
    ctx = BN_CTX_new();
    if (1 != EC_POINT_mul(ecgrp, pt_a, r_bn, NULL, NULL, ctx)) {
        LOGD("EC multiplication failed: [r]P_1");
    }
    // B=[y]A
    BN_CTX_free(ctx); // TODO: Seriously necessary?
    ctx = BN_CTX_new();

    if (1 != EC_POINT_mul(ecgrp, pt_b, NULL, pt_a, sk_y_bn, ctx)) {
        LOGD("EC multiplication failed: [y]A");
    }

    BN_CTX_free(ctx); // TODO: Seriously necessary?
    ctx = BN_CTX_new();
    if (1 != BN_mod_mul(ry_bn, r_bn, sk_y_bn, order_bn, ctx)) {
        LOGD("Modular multiplication failed ry");
    }
    // D=[ry]Q_s

    BN_CTX_free(ctx); // TODO: Seriously necessary?
    ctx = BN_CTX_new();
    if (1 != EC_POINT_mul(ecgrp, pt_d, NULL, pt_qs, ry_bn, ctx)) {
        LOGD("EC multiplication failed: [ry]Q_s");
    }
    // tmp=A+D

    BN_CTX_free(ctx); // TODO: Seriously necessary?
    ctx = BN_CTX_new();
    if (1 != EC_POINT_add(ecgrp, pt_tmp, pt_a, pt_d, ctx)) {
        LOGD("ec_point_add failed A+D");
    }
    // C=[x]tmp

    BN_CTX_free(ctx); // TODO: Seriously necessary?
    ctx = BN_CTX_new();
    if (1 != EC_POINT_mul(ecgrp, pt_c, NULL, pt_tmp, sk_x_bn, ctx)) {
        LOGD("EC multiplication failed: [ry]Q_s");
    }
    BN_CTX_free(ctx); // TODO: Seriously necessary?

    // Now we generate our signature
    //TODO: Build signature...MakeCre


    // Now we can build the credential
    // We build the credentials as A_X || A_Y || B_X || B_Y.......
    // Meaning we have 8x32 = 256 bytes

    getBinaryCoordinates(pt_a, &credentialBuffer[daaCtx->ecc_point_len * 0],
                         &credentialBuffer[daaCtx->ecc_point_len * 1]);
    getBinaryCoordinates(pt_b, &credentialBuffer[daaCtx->ecc_point_len * 2],
                         &credentialBuffer[daaCtx->ecc_point_len * 3]);
    getBinaryCoordinates(pt_c, &credentialBuffer[daaCtx->ecc_point_len * 4],
                         &credentialBuffer[daaCtx->ecc_point_len * 5]);
    getBinaryCoordinates(pt_d, &credentialBuffer[daaCtx->ecc_point_len * 6],
                         &credentialBuffer[daaCtx->ecc_point_len * 7]);


    // Now cleanup
    BN_free(sk_x_bn);
    BN_free(sk_y_bn);
    BN_free(order_bn);
    BN_free(r_bn);
    BN_free(ry_bn);
    BN_free(daa_x_bn);
    BN_free(daa_y_bn);

    EC_POINT_free(pt_qs);
    EC_POINT_free(pt_a);
    EC_POINT_free(pt_b);
    EC_POINT_free(pt_c);
    EC_POINT_free(pt_d);
    EC_POINT_free(pt_tmp);

    EC_GROUP_free(ecgrp);


}

/*
 * Function:  daa_initiate_join
 * --------------------
 *  The first step of the join phase, where the DAA Prover registers its DAA key and EK with the Issuer
 *
 *  ctx:                    The DAA Context (needed to determine algorithms)
 *  daa_pub:                The DAA Public Key
 *  ek_pub:                 The Endorsement Key Public Key
 *
 *  returns: a challenge credential to the Prover
 */
CHALLENGE_CREDENTIAL
daa_initiate_join(DAA_CONTEXT *ctx, ECC_POINT *daa_pub, uint8_t *daa_tpm_name, uint8_t *ek_pub) {

    //TODO: Of course this should be stored in a better way
    daa_stored = *daa_pub;

    memcpy(ek_stored, ek_pub, ctx->ek_pk_len);
    memcpy(daa_name, daa_tpm_name, ctx->name_len);

    return make_credential_data(ctx);
}

/*
 * Function:  daa_on_host_response
 * --------------------
 *  The second part of the join phase, where the issuer verifies the host response and issues a credential
 *
 *  ctx:                    The DAA Context (needed to determine algorithms)
 *  credentialKey           The Credential Key used by the Prover
 *  sig:                    The DAA Signature over the challenge
 *  newSignature            1 if new 0 otherwise
 *
 *  returns: an encrypted full credential
 */
FULL_CREDENTIAL
daa_on_host_response(DAA_CONTEXT *ctx, uint8_t *credentialKey, DAA_SIGNATURE *sig, int8_t newSignature) {
    FULL_CREDENTIAL result;

    // check K1 (Verify credentialKey)
    if (memcmp(credentialKey, credentialKey_local, ctx->symmetric_key_bytes) != 0) {
        LOGD("[-] Wrong credential key provided\n");
    }
    // We then re-create the host_string (X,Y, CK, EK_pub)
    uint8_t host_str[ctx->iss_pk_len + ctx->symmetric_key_bytes + ctx->ek_pk_len];

    recalculate_host_string(ctx, ek_stored, credentialKey, host_str);

    if (issuer_verify_signature(ctx, sig, newSignature, host_str) != EXIT_SUCCESS) {
        LOGD("[-] Issuer couldn't verify signature\n");
    }


    CHALLENGE_CREDENTIAL c = make_credential_data(ctx); // @1;
    uint8_t daa_credential[256];

    make_daa_credential(ctx, &daa_stored, daa_credential);


    encryptAES(ctx, daa_credential, 256, credentialKey_local, ctx->symmetric_key_bytes,
               "AES-128-CTR", result.credentialEncrypted);

    result.join_credential = c;

    result.encryptedLength = 256;

    return result;
}

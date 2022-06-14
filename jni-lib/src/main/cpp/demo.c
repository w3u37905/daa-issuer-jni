#include <stdio.h>
#include <openssl/evp.h>
#include <DAA-Bridge_v2/Test_issuer/issuer_interface.h>
#include <openssl/err.h>
#include "bridge_tpm.h"
#include "templates.h"
#include "defines.h"
#include "daa_bridge.h"
#include "cryptoutils.h"
#include "objecttemplates.h"


int wallet_sign_nonce(TPM2B_NONCE *nonce, uint8_t *digestOut, char *keyLocation, uint8_t *signatureOut) {
    EVP_PKEY *key;
    size_t sigLen;
    unsigned int mdLen;
    FILE *pemKeyFile = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t req = 0;
    uint8_t *signatureLocal;
    ctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_get_digestbyname("SHA256");

    // Set digest 0
    memset(digestOut, 0, DIGEST_SIZE);

    TSS_File_Open(&pemKeyFile, keyLocation, "rb");    /* closed @2 */
    if (pemKeyFile == NULL) {
        printf("Pem Keyfile null\n");
    }
    key = PEM_read_PrivateKey(pemKeyFile, NULL, NULL, NULL);

    if (key == NULL) {
        printf("Key is null\n");
    }

    // Calculate Authorized Digest

    // Initialize digest
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        printf("[-] EVP DigestInit error\n");
    }

    // Initialize signing
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) != 1) {
        printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    }

    uint8_t expirate[4] = {0x00, 0x00, 0x00, 0x00};


    // Update with nonce
    if (EVP_DigestUpdate(ctx, nonce->t.buffer, nonce->t.size) != 1) {
        printf("[-] EVP DigestUpdate error\n");
    }
    // Update with expiration
    if (EVP_DigestUpdate(ctx, expirate, 4) != 1) {
        printf("[-] EVP Digest error\n");
    }

    // Get signature size
    if (EVP_DigestSignFinal(ctx, NULL, &req) != 1) {
        printf("[-] EVP DigestFinal error\n");
    }
    signatureLocal = OPENSSL_malloc(req);
    if (signatureLocal == NULL) {
        printf("[-] Not able to Malloc %zu bytes\n", req);
    }


    // Get signature
    if (EVP_DigestSignFinal(ctx, signatureLocal, &req) != 1) {
        printf("[-] EVP DigestFinal (2) error\n");
        printf("DigestFinal 2 failed, error lol 0x%lx\n", ERR_get_error());
    }

    sigLen = req;

    // Get digest
    EVP_DigestFinal(ctx, digestOut, &mdLen);


    if (ctx) {
        EVP_MD_CTX_destroy(ctx);
        ctx = NULL;
    }
    fclose(pemKeyFile);
    EVP_PKEY_free(key);

    printf("[+] Signed Authorization (Wallet)\n");

    memcpy(signatureOut, signatureLocal, sigLen);
    OPENSSL_free(signatureLocal);

    return sigLen;


}


int main() {
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    printf("Hello, World!\n");


    //loadIssuerAuthorizationKey();
    TPM2B_PUBLIC ek = setup();

    // Act as wallet //
    TPM2B_NONCE nonce;

    uint8_t nonce_digest[SHA256_DIGEST_SIZE];
    uint8_t nonce_sig[150];
    printf("\n[ \t Wallet Requesting & Signing Nonce \t]\n");

    requestNonce(&nonce);
    clock_t t;
    t = clock();
    int len = wallet_sign_nonce(&nonce, nonce_digest, "/home/benlar/Projects/DAA-Bridge_v2/Wallet_keys/key.pem",
                                nonce_sig);


    printf("\n[ \t Bridge Informed to Create New Attestation Key \t]\n");
    onNewSessionFromVCIssuer(&ek, nonce_sig, len);
    t = clock() - t;
    double time_taken = ((double) t) / CLOCKS_PER_SEC; // in seconds

    printf("Time taken (Create, join, verify): %fms\n", time_taken * 1000);


    printf("\n[ \t Wallet Signs Nonce to Authorize a Sign Operation\t]\n");

    requestNonce(&nonce);
    len = wallet_sign_nonce(&nonce, nonce_digest, "/home/benlar/Projects/DAA-Bridge_v2/Wallet_keys/key.pem", nonce_sig);

    uint8_t msg[10];
    RAND_bytes(msg, 10);


    execute_daa_sign(msg, 10, nonce_sig, len);

    //  onCreateAttestationKeyCommand(&iss_pk);

    finalizeContext();

    return 0;


}

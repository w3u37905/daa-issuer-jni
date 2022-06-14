//
// Created by benlar on 1/7/22.
//
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>
#include <stdlib.h>
#include "../cryptoutils.h"
#include "../objecttemplates.h"
#include "../daa/daa_issuer.h"
#include "../defines.h"
#include "../daa_bridge.h"
#include "../daa/daa_client_base.h"
#include "memory.h"
#include "../policy.h"
#include <openssl/err.h>
#include "openssl/evp.h"
#include "openssl/ec.h"
#include "issuer_interface.h"

#include <android/log.h>
#include <cJSON.h>

#define  LOG_TAG    "DAA-BRIDGE"

#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


TPM2B_PUBLIC client_ek;
TPM2B_PUBLIC client_wk;
uint8_t issuer_nae[NAME_LEN]; // TODO: This should be made and conveted somewhere

uint8_t correct_policy[DIGEST_SIZE];


int buildIssuerChallenge(CHALLENGE_CREDENTIAL c, AUTHORIZATION signAuth, AUTHORIZATION commitAuth,
                         TPML_PCR_SELECTION select, char *bufferOut);

DOOR_ISSUER_REGISTRATION getRegistrationFromJSON(const char *json);

CHALLENGE_RESPONSE parseChallengeResponse(const char *json);

char *marshalFullCredential(FULL_CREDENTIAL *ptr);

TPML_PCR_SELECTION getPCRSelection(int num, ...) {
    TPML_PCR_SELECTION selection;
    selection.count = 1; // We only have one bank (could be multiple ofc)
    selection.pcrSelections[0].hash = HASH_ALG;
    selection.pcrSelections[0].sizeofSelect = 3;    /* hard code 24 PCRs */
    va_list valist;
    va_start(valist, num);

    for (int i = 0; i < 8; i++)
        selection.pcrSelections[0].pcrSelect[i] = 0x00;

    for (int i = 0; i < num; i++) {
        int bit = va_arg(valist, int);
        int bitToSet = ((bit - 1) % 8);
        int byteToSet = (int) ((bit - 1) / 8);
        selection.pcrSelections[0].pcrSelect[byteToSet] |= 1 << bitToSet;
    }

    return selection;
}

void getNameFromPublic(TPMT_PUBLIC *publicKey, unsigned char *nameOut) {
    TPM2B_TEMPLATE marshaled;
    TPMT_HA name;
    uint16_t written;
    uint32_t size;
    uint8_t *buffer;

    name.hashAlg = publicKey->nameAlg;

    written = 0;
    size = sizeof(marshaled.t.buffer);
    buffer = marshaled.t.buffer;

    int rc = TSS_TPMT_PUBLIC_Marshalu(publicKey, &written, &buffer, &size);
    marshaled.t.size = written;

    if (rc == 0) {
        rc = TSS_Hash_Generate(&name, marshaled.t.size, marshaled.t.buffer, 0, NULL);
    } else {
        LOGD("[-] Error in marshaling key\n");
    }


    nameOut[0] = name.hashAlg >> 8;
    nameOut[1] = name.hashAlg & 0xff;
    memcpy(&nameOut[2], name.digest.tssmax, SHA256_DIGEST_SIZE);

}

void setIssuerName() {
    TPM2B_PUBLIC pk;
    convertEcPemToPublic(&pk, TYPE_SI, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA256,
                         "/sdcard/Documents/TPM/IS.pem");
    getNameFromPublic(&pk.publicArea, issuer_nae);
}

void loadWalletKey() {
    convertEcPemToPublic(&client_wk, TYPE_SI, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA256,
                         "/sdcard/Documents/TPM/WK.pem");

}

TPM2B_PUBLIC loadIssuerAuthorizationKey() {

    TPM2B_PUBLIC pk;

    convertEcPemToPublic(&pk, TYPE_SI, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA256,
                         "/sdcard/Documents/TPM/IS.pem");

    return pk;

}

void onNewSessionFromVCIssuer(TPM2B_PUBLIC *EK, uint8_t *signedNonce, int nonceLen) {
    client_ek = *EK;
    unsigned char cc[4] = {0x00, 0x00, 0x01, 0x6a};
    setIssuerName();

    loadWalletKey();
    // Set correct policy
    memset(correct_policy, 0, DIGEST_SIZE);
    hash_begin(HASH_ALG);
    hash_update(correct_policy, DIGEST_SIZE);
    hash_update(cc, 4);
    hash_update(issuer_nae, NAME_LEN);
    hash_final(correct_policy);

    hash_begin(HASH_ALG);
    hash_update(correct_policy, DIGEST_SIZE);
    hash_final(correct_policy);
    TPM2B_PUBLIC iss_pk = loadIssuerAuthorizationKey();



    //TODO: Return JSON
    // iSSpK, SIGNEDnONCE AND nONnceLen should be sent back to someone
    //onCreateAttestationKeyCommand(&iss_pk, signedNonce,nonceLen);

}


void get_state_data(TPML_PCR_SELECTION *pcr, uint8_t *state_digest) {

    memset(state_digest, 0, DIGEST_SIZE);
    hash_begin(HASH_ALG);

    hash_update(state_digest, DIGEST_SIZE);
    hash_update(state_digest, DIGEST_SIZE);
    hash_final(state_digest);

}


void get_policy_digest(TPML_PCR_SELECTION *pcr_selection, uint8_t *expected_state_digest,
                       uint8_t *policy_digest) {
    uint8_t wk_name[NAME_LEN];

    // Get name of Wallet Key
    getNameFromPublic(&client_wk.publicArea, wk_name);



    // Clear policyDigest;
    memset(policy_digest, 0, DIGEST_SIZE);

    // Begin by updating with PolicySigned
    updatePolicySigned(wk_name, NAME_LEN, policy_digest);

    // Update with PolicyPCR
    updatePolicyPCR(pcr_selection, expected_state_digest, policy_digest);

}

void cc_to_byteArray_iss(uint16_t cc, uint8_t *out) {
    out[0] = (cc >> 24) & 0xFF;
    out[1] = (cc >> 16) & 0xFF;
    out[2] = (cc >> 8) & 0xFF;
    out[3] = (cc >> 0) & 0xFF;
}

size_t build_join_authorization(char *keyLocation, uint8_t *signature, uint8_t *digestOut,
                                uint8_t *approvedPolicy) {
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

    pemKeyFile = fopen(keyLocation, "rb");
    if (pemKeyFile == NULL) {
        LOGD("Pem Keyfile null\n");
    }
    key = PEM_read_PrivateKey(pemKeyFile, NULL, NULL, NULL);

    if (key == NULL) {
        LOGD("Key is null\n");
    }

    // Calculate Authorized Digest

    hash_begin(HASH_ALG);
    unsigned char pcc[4];
    unsigned char cc[4];
    cc_to_byteArray_iss(TPM_CC_PolicyCommandCode, pcc);
    cc_to_byteArray_iss(TPM_CC_Commit, cc);


    memset(approvedPolicy, 0, 32);

    hash_update(approvedPolicy, 32);
    hash_update(pcc, 4);
    hash_update(cc, 4);
    hash_final(approvedPolicy);

    // Initialize digest
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        LOGD("[-] EVP DigestInit error\n");
    }

    // Initialize signing
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) != 1) {
        LOGD("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    }

    // Update with policy digest
    if (EVP_DigestUpdate(ctx, approvedPolicy, DIGEST_SIZE) != 1) {
        LOGD("[-] EVP SignUpdate error\n");
    }

    // Get signature size
    if (EVP_DigestSignFinal(ctx, NULL, &req) != 1) {
        LOGD("[-] EVP DigestFinal error\n");
    }
    signatureLocal = OPENSSL_malloc(req);

    // Get signature
    if (signatureLocal == NULL) {
        LOGD("Not able to allocate %zu bytes\n", req);
    }
    if (EVP_DigestSignFinal(ctx, signatureLocal, &req) != 1) {
        LOGD("[-] EVP DigestFinal (2) error (Issuer)\n");
        LOGD("DigestFinal 2 failed, error 0x%lx\n", ERR_get_error());

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

    LOGD("[+] Signed Authorization (Issuer, Join)\n");

    memcpy(signature, signatureLocal, sigLen);
    OPENSSL_free(signatureLocal);

    return sigLen;

}


size_t build_sign_authorization(char *keyLocation, uint8_t *signature, uint8_t *digestOut,
                                TPML_PCR_SELECTION *pcr, uint8_t *approvedPolicy) {
    EVP_PKEY *key;
    size_t sigLen;
    unsigned int mdLen;
    FILE *pemKeyFile = NULL;
    EVP_MD_CTX *ctx = NULL;
    size_t req = 0;
    uint8_t *signatureLocal;
    ctx = EVP_MD_CTX_create();
    const EVP_MD *md = EVP_get_digestbyname("SHA256");
    uint8_t state_digest[SHA256_DIGEST_SIZE];
    uint8_t policy_inner[SHA256_DIGEST_SIZE];

    get_state_data(pcr, state_digest);
    memset(approvedPolicy, 0, 32);
    get_policy_digest(pcr, state_digest, approvedPolicy);
    memcpy(policy_inner, approvedPolicy, SHA256_DIGEST_SIZE);

    // Set digest 0
    memset(digestOut, 0, DIGEST_SIZE);

    TSS_File_Open(&pemKeyFile, keyLocation, "rb");    /* closed @2 */
    if (pemKeyFile == NULL) {
        LOGD("Pem Keyfile null\n");
    }
    key = PEM_read_PrivateKey(pemKeyFile, NULL, NULL, NULL);

    if (key == NULL) {
        LOGD("Key is null\n");
    }

    // Initialize digest
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        LOGD("[-] EVP DigestInit error\n");
    }

    // Initialize signing
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) != 1) {
        LOGD("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    }

    // Update with policy digest
    if (EVP_DigestUpdate(ctx, policy_inner, DIGEST_SIZE) != 1) {
        LOGD("[-] EVP SignUpdate error\n");
    }

    // Get signature size
    if (EVP_DigestSignFinal(ctx, NULL, &req) != 1) {
        LOGD("[-] EVP DigestFinal error\n");
    }
    signatureLocal = OPENSSL_malloc(req);

    // Get signature
    if (signatureLocal == NULL) {
        LOGD("Not able to allocate %zu bytes\n", req);
    }
    if (EVP_DigestSignFinal(ctx, signatureLocal, &req) != 1) {
        LOGD("[-] EVP DigestFinal (2) error (Issuer)\n");
        LOGD("DigestFinal 2 failed, error 0x%lx\n", ERR_get_error());

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

    LOGD("[+] Signed Authorization (Issuer, Sign)\n");

    memcpy(signature, signatureLocal, sigLen);
    OPENSSL_free(signatureLocal);

    return sigLen;


}


char *send_issuer_registration(const char *json) {
    // We pretend to be the issuer here

    DOOR_ISSUER_REGISTRATION reg = getRegistrationFromJSON(json);
    DOOR_ISSUER_REGISTRATION *registrationPackage = &reg; // lazy fix
    client_ek = registrationPackage->ekPub;
    unsigned char cc[4] = {0x00, 0x00, 0x01, 0x6a};
    setIssuerName();

    loadWalletKey();
    // Set correct policy
    memset(correct_policy, 0, DIGEST_SIZE);
    hash_begin(HASH_ALG);
    hash_update(correct_policy, DIGEST_SIZE);
    hash_update(cc, 4);
    hash_update(issuer_nae, NAME_LEN);
    hash_final(correct_policy);

    hash_begin(HASH_ALG);
    hash_update(correct_policy, DIGEST_SIZE);
    hash_final(correct_policy);


    unsigned char daa_name[NAME_LEN];
    LOGD("\n[ \t DOOR Issuer Received Keys \t]\n");


    AUTHORIZATION signAuth, commitAuth;

    // Step 2: Calculate the name of the provided key
    getNameFromPublic(&registrationPackage->akPub, daa_name);

    // Step 3: Verify the provided key is the one attested


    // Step 5: Verify the policy is PolicyAuthorize(Isssuer)
    if (memcmp(correct_policy, registrationPackage->akPub.authPolicy.t.buffer, DIGEST_SIZE) != 0) {
        LOGD("[-] Issuer couldn't verify key policy)\n");
        exit(-1);
    } else {
        LOGD("[+] Provided key has correct policy\n");
    }


    // Check that we have the right policy requirements
    if ((registrationPackage->akPub.objectAttributes.val & TPMA_OBJECT_ADMINWITHPOLICY) ||
        registrationPackage->akPub.objectAttributes.val & TPMA_OBJECT_USERWITHAUTH) {

        LOGD("[-] Key Attributes are wrong (Policy)\n");
        exit(-1);
    } else {
        LOGD("[+] Key Attributes OK\n");
    }


    // Step 6: Build Authorized Policy (Signed WK, PolicyPCR)
    //build_authorization(authorized_digest);

    // Step 7a: Sign the join digest ( for commit )
    LOGD("\n[ \t DOOR Issuer Authorizes Key to Commit \t]\n");
    commitAuth.sigLen = build_join_authorization("sdcard/Documents/TPM/IS_priv.pem",
                                                 commitAuth.signature, commitAuth.digest,
                                                 commitAuth.approvedPolicy);


    LOGD("\n[ \t DOOR Issuer Authorizes Key to be use in PCR and Signed Context (By Wallet)\t]\n");
    // Step 7: Sign the authorized digest
    TPML_PCR_SELECTION select = getPCRSelection(2, 1, 12);
    signAuth.sigLen = build_sign_authorization("sdcard/Documents/TPM/IS_priv.pem",
                                               signAuth.signature,
                                               signAuth.digest, &select, signAuth.approvedPolicy);


    // Step 8: Execute DAA Join
    DAA_CONTEXT *ctx = new_daa_context();
    ECC_POINT daa;
    memcpy(daa.x_coord, registrationPackage->akPub.unique.ecc.x.t.buffer,
           registrationPackage->akPub.unique.ecc.x.t.size);
    memcpy(daa.y_coord, registrationPackage->akPub.unique.ecc.y.t.buffer,
           registrationPackage->akPub.unique.ecc.y.t.size);
    daa.coord_len = registrationPackage->akPub.unique.ecc.y.t.size;

    LOGD("\n[ \t Issuer Creating Challenge Credential (DAA Join) \t]\n");


    CHALLENGE_CREDENTIAL c = daa_initiate_join(ctx, &daa, daa_name,
                                               client_ek.publicArea.unique.rsa.t.buffer);
    free_daa_context(ctx);

    // Step 9: Return data to Bridge
    char *challenge_cred = malloc(4000);
    int size = buildIssuerChallenge(c, signAuth, commitAuth, select, challenge_cred);

    LOGD("Length of challenge_cred = %d\n", size);
    return challenge_cred;
}

char *send_challenge_response(const char *json) {

    CHALLENGE_RESPONSE challengeResponse = parseChallengeResponse(json);
    DAA_CONTEXT *ctx = new_daa_context();

    LOGD("ChallengeResponse signature:");



    FULL_CREDENTIAL fcre = daa_on_host_response(ctx, challengeResponse.credneitalKey,
                                                &challengeResponse.sig, 1);
    free_daa_context(ctx);

    return marshalFullCredential(&fcre);


}

char *marshalFullCredential(FULL_CREDENTIAL *fcre) {
    cJSON *root = NULL;
    root = cJSON_CreateObject();

    cJSON *challengeCredential = cJSON_CreateObject();

    // Credential
    cJSON *challengeArr = cJSON_CreateArray();
    for (int i = 0; i < fcre->join_credential.credential_length; i++) {
        cJSON *byte = cJSON_CreateNumber(fcre->join_credential.credential[i]);
        cJSON_AddItemToArray(challengeArr, byte);
    }

    // Secret
    cJSON *secretArray = cJSON_CreateArray();
    for (int i = 0; i < fcre->join_credential.secret_length; i++) {
        cJSON *byte = cJSON_CreateNumber(fcre->join_credential.secret[i]);
        cJSON_AddItemToArray(secretArray, byte);
    }

    // encrypted
    cJSON *encryptedArray = cJSON_CreateArray();
    for (int i = 0; i < fcre->encryptedLength; i++) {
        cJSON *byte = cJSON_CreateNumber(fcre->credentialEncrypted[i]);
        cJSON_AddItemToArray(encryptedArray, byte);
    }

    cJSON_AddItemToObject(root, "encryptedCredential", encryptedArray);


    // Add them to the credential
    cJSON_AddItemToObject(challengeCredential, "credential", challengeArr);
    cJSON_AddItemToObject(challengeCredential, "secret", secretArray);

    // Now add it to the structure
    cJSON_AddItemToObject(root, "joinCredential", challengeCredential);

    return cJSON_PrintUnformatted(root);

}

DAA_SIGNATURE parseDAASignature(char *name, const char *json) {

    DAA_SIGNATURE daaSig;
    cJSON *root = cJSON_Parse(json);
    cJSON *daaSignature = cJSON_GetObjectItem(root, name);
    cJSON *daaCredential = cJSON_GetObjectItem(daaSignature, "daa_credential");

    cJSON *p1x = cJSON_GetObjectItem(daaCredential, "p1_x");
    cJSON *p1y = cJSON_GetObjectItem(daaCredential, "p1_y");
    cJSON *p2x = cJSON_GetObjectItem(daaCredential, "p2_x");
    cJSON *p2y = cJSON_GetObjectItem(daaCredential, "p2_y");
    cJSON *p3x = cJSON_GetObjectItem(daaCredential, "p3_x");
    cJSON *p3y = cJSON_GetObjectItem(daaCredential, "p3_y");
    cJSON *p4x = cJSON_GetObjectItem(daaCredential, "p4_x");
    cJSON *p4y = cJSON_GetObjectItem(daaCredential, "p4_y");

    cJSON *sigS = cJSON_GetObjectItem(daaSignature, "sigS");
    cJSON *sigR = cJSON_GetObjectItem(daaSignature, "sigR");
    cJSON *V = cJSON_GetObjectItem(daaSignature, "V");

    cJSON *iterator = NULL;
    int i = 0;
    cJSON_ArrayForEach(iterator, p1x) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[0].x_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    daaSig.rcre.points[0].coord_len = i;

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, p1y) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[0].y_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, p2x) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[1].x_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    daaSig.rcre.points[1].coord_len = i;

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, p2y) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[1].y_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, p3x) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[2].x_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    daaSig.rcre.points[2].coord_len = i;

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, p3y) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[2].y_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, p4x) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[3].x_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, p4y) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.rcre.points[3].y_coord[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    daaSig.rcre.points[3].coord_len = i;

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, sigS) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.signatureS[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, sigR) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.signatureR[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    iterator = NULL;
    i = 0;
    cJSON_ArrayForEach(iterator, V) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.V[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    cJSON_Delete(root);

    return daaSig;
}

CHALLENGE_RESPONSE parseChallengeResponse(const char *json) {
    CHALLENGE_RESPONSE result;

    cJSON *root = cJSON_Parse(json);
    cJSON *credentialKey = cJSON_GetObjectItem(root, "credentialKey");

    cJSON *iterator = NULL;
    result.certLen = 0;

    // Get CredentialKey
    cJSON_ArrayForEach(iterator, credentialKey) {
        if (cJSON_IsNumber(iterator)) {
            result.credneitalKey[result.certLen++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    result.sig = parseDAASignature("daaSignature", json);

    return result;
}

DOOR_ISSUER_REGISTRATION getRegistrationFromJSON(const char *data) {
    DOOR_ISSUER_REGISTRATION issuerRegistration;

    cJSON *root = cJSON_Parse(data);
    cJSON *daaKey = cJSON_GetObjectItem(root, "daaKey");
    cJSON *endorsementKey = cJSON_GetObjectItem(root, "endorsementKey");

    cJSON *iterator = NULL;
    uint8_t daa[1000];
    uint8_t localEK[1000];
    uint32_t daaLen = 0;
    uint32_t ekLen = 0;


    cJSON_ArrayForEach(iterator, daaKey) {
        if (cJSON_IsNumber(iterator)) {
            daa[daaLen++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    cJSON_ArrayForEach(iterator, endorsementKey) {
        if (cJSON_IsNumber(iterator)) {
            localEK[ekLen++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    cJSON_Delete(root);


    // Now parse them
    uint8_t *ekPtr = localEK;
    uint8_t *akPtr = daa;

    TSS_TPM2B_PUBLIC_Unmarshalu(&issuerRegistration.ekPub, &ekPtr, &ekLen, 0);
    TSS_TPMT_PUBLIC_Unmarshalu(&issuerRegistration.akPub, &akPtr, &daaLen, 0);

    return issuerRegistration;
}


int buildIssuerChallenge(CHALLENGE_CREDENTIAL c, AUTHORIZATION signAuth, AUTHORIZATION commitAuth,
                         TPML_PCR_SELECTION select, char *bufferOut) {
    cJSON *root = NULL;
    root = cJSON_CreateObject();


    // Add Challenge Credential
    /*
     *     uint8_t credential[MAX_JOIN_CRED_LENGTH];
     *     uint8_t secret[MAX_SECRET_LENGTH];
     *     int credential_length;
     *     int secret_length;
     * */
    LOGD("Challenge Credential JSON\n");
    cJSON *challengeCredential = cJSON_CreateObject();

    // Credential
    cJSON *challengeArr = cJSON_CreateArray();
    for (int i = 0; i < c.credential_length; i++) {
        cJSON *byte = cJSON_CreateNumber(c.credential[i]);
        cJSON_AddItemToArray(challengeArr, byte);
    }

    // Secret
    cJSON *secretArray = cJSON_CreateArray();
    for (int i = 0; i < c.secret_length; i++) {
        cJSON *byte = cJSON_CreateNumber(c.secret[i]);
        cJSON_AddItemToArray(secretArray, byte);
    }

    // Add them to the credential
    cJSON_AddItemToObject(challengeCredential, "credential", challengeArr);
    cJSON_AddItemToObject(challengeCredential, "secret", secretArray);

    // Now add it to the structure
    cJSON_AddItemToObject(root, "challengeCredential", challengeCredential);


    // Now let's add the two authorizations

    /*
     *  typedef struct{
        size_t sigLen;
        uint8_t signature[150];
        uint8_t digest[DIGEST_SIZE];
        uint8_t approvedPolicy[DIGEST_SIZE];
} AUTHORIZATION;
     *
     * */
    LOGD("Authorization JSON\n");

    cJSON *commitAuthorization = cJSON_CreateObject();

    // Add Signature
    cJSON *commitAuthSigArr = cJSON_CreateArray();
    for (int i = 0; i < commitAuth.sigLen; i++) {
        cJSON *byte = cJSON_CreateNumber(commitAuth.signature[i]);
        cJSON_AddItemToArray(commitAuthSigArr, byte);
    }

    // Add digest
    cJSON *commitAuthDigestArr = cJSON_CreateArray();
    for (int i = 0; i < DIGEST_SIZE; i++) {
        cJSON *byte = cJSON_CreateNumber(commitAuth.digest[i]);
        cJSON_AddItemToArray(commitAuthDigestArr, byte);
    }

    // Add approved
    cJSON *commitAuthApprovedArr = cJSON_CreateArray();
    for (int i = 0; i < DIGEST_SIZE; i++) {
        cJSON *byte = cJSON_CreateNumber(commitAuth.approvedPolicy[i]);
        cJSON_AddItemToArray(commitAuthApprovedArr, byte);
    }

    // Add them to the credential
    cJSON_AddItemToObject(commitAuthorization, "signature", commitAuthSigArr);
    cJSON_AddItemToObject(commitAuthorization, "digest", commitAuthDigestArr);
    cJSON_AddItemToObject(commitAuthorization, "approvedPolicy", commitAuthApprovedArr);

    // Now add it to the structure
    cJSON_AddItemToObject(root, "commitAuthorization", commitAuthorization);

    // Do the same for sign authorization

    cJSON *signAuthorization = cJSON_CreateObject();

    // Add Signature
    cJSON *signAuthSigArr = cJSON_CreateArray();
    for (int i = 0; i < signAuth.sigLen; i++) {
        cJSON *byte = cJSON_CreateNumber(signAuth.signature[i]);
        cJSON_AddItemToArray(signAuthSigArr, byte);
    }

    // Add digest
    cJSON *signAuthDigestArr = cJSON_CreateArray();
    for (int i = 0; i < DIGEST_SIZE; i++) {
        cJSON *byte = cJSON_CreateNumber(signAuth.digest[i]);
        cJSON_AddItemToArray(signAuthDigestArr, byte);
    }

    // Add approved
    cJSON *signAuthApprovedArr = cJSON_CreateArray();
    for (int i = 0; i < DIGEST_SIZE; i++) {
        cJSON *byte = cJSON_CreateNumber(signAuth.approvedPolicy[i]);
        cJSON_AddItemToArray(signAuthApprovedArr, byte);
    }

    // Add them to the credential
    cJSON_AddItemToObject(signAuthorization, "signature", signAuthSigArr);
    cJSON_AddItemToObject(signAuthorization, "digest", signAuthDigestArr);
    cJSON_AddItemToObject(signAuthorization, "approvedPolicy", signAuthApprovedArr);

    // Now add it to the structure
    cJSON_AddItemToObject(root, "signAuthorization", signAuthorization);

    LOGD("PCR Select JSON\n");

    // Finally we marshal the PCR selection
    uint16_t written = 0;
    uint8_t *selectPtr;
    int rc = TSS_Structure_Marshal(&selectPtr, &written, &select,
                                   (MarshalFunction_t) TSS_TPML_PCR_SELECTION_Marshalu);
    LOGD("Mashal succes: %d, written %d", rc, written);

    for (int i = 0; i < written; i++) {
        LOGD("%02x", selectPtr[i]);
    }

    cJSON *pcrSelectArr = cJSON_CreateArray();
    for (int i = 0; i < written; i++) {
        cJSON *byte = cJSON_CreateNumber(selectPtr[i]);
        cJSON_AddItemToArray(pcrSelectArr, byte);
    }

    cJSON_AddItemToObject(root, "pcrSelection", pcrSelectArr);


    char *json = cJSON_PrintUnformatted(root);
    memcpy(bufferOut, json, strlen(json));

    return strlen(json);


}

void onNewSessionFromVCIssuer_json(char *information) {

    TPM2B_NONCE nonce;


}

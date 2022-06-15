#include <iostream>
#include "jni_DAAInterface.h"
#include <jni.h>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "bridge_tpm.h"
#include "daa_bridge.h"

#include "Test_issuer/issuer_interface.h"
#include "objecttemplates.h"
#include "cryptoutils.h"
#include <openssl/rand.h>
#include <cJSON.h>


#define  LOG_TAG    "DAA-NATIVE"

#define  LOGD(...)  printf(__VA_ARGS__)
#define  LOGE(...)  printf(__VA_ARGS__)


TPM2B_PUBLIC ek;
char jsonBuffer[4000];


void marshalDAASignature(DAA_SIGNATURE *ptr, unsigned char* bufferOut);

int wallet_sign_nonce(TPM2B_NONCE *nonce, uint8_t *digestOut, char *keyLocation,
                      uint8_t *signatureOut) {
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

    pemKeyFile = fopen("/sdcard/Documents/TPM/WK_priv.pem", "r");
    if (pemKeyFile == NULL) {
        LOGD("Pem Keyfile null....\n");
    }
    key = PEM_read_PrivateKey(pemKeyFile, NULL, NULL, NULL);

    if (key == NULL) {
        LOGD("Key is null\n");
    }

    // Calculate Authorized Digest

    // Initialize digest
    if (EVP_DigestInit_ex(ctx, md, NULL) != 1) {
        LOGD("[-] EVP DigestInit error\n");
    }

    // Initialize signing
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, key) != 1) {
        LOGD("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    }

    uint8_t expirate[4] = {0x00, 0x00, 0x00, 0x00};


    // Update with nonce
    if (EVP_DigestUpdate(ctx, nonce->t.buffer, nonce->t.size) != 1) {
        LOGD("[-] EVP DigestUpdate error\n");
    }
    // Update with expiration
    if (EVP_DigestUpdate(ctx, expirate, 4) != 1) {
        LOGD("[-] EVP Digest error\n");
    }

    // Get signature size
    if (EVP_DigestSignFinal(ctx, NULL, &req) != 1) {
        LOGD("[-] EVP DigestFinal error\n");
    }
    signatureLocal = (uint8_t *) OPENSSL_malloc(req);
    if (signatureLocal == NULL) {
        LOGD("[-] Not able to Malloc %zu bytes\n", req);
    }


    // Get signature
    if (EVP_DigestSignFinal(ctx, signatureLocal, &req) != 1) {
        LOGD("[-] EVP DigestFinal (2) error\n");
        LOGD("DigestFinal 2 failed, error lol 0x%lx\n", ERR_get_error());
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

    LOGD("[+] Signed Authorization (Wallet)\n");

    memcpy(signatureOut, signatureLocal, sigLen);
    OPENSSL_free(signatureLocal);

    return sigLen;


}

JNIEXPORT jstring JNICALL Java_jni_DAAInterface_bar(JNIEnv *env, jobject thisObject)
{
  std::string res("bar");
  return env->NewStringUTF(res.c_str());
}


extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_getByteString(JNIEnv *env, jobject thiz) {
    // TODO: implement getByteString()

    uint8_t buff[5];
    tpm2_GetRandom(4, buff);
    char myString[30];
    sprintf(myString, "0x%02x, 0x%02x\n0x%02x, 0x%02x", buff[0], buff[1], buff[2], buff[3]);
    return (*env).NewStringUTF(myString);
}


extern "C"
JNIEXPORT void JNICALL
Java_jni_DAAInterface_initializeTPM(JNIEnv *env, jobject thiz) {
    ek = setup();

}


extern "C"
JNIEXPORT void JNICALL
Java_jni_DAAInterface_registerWalletPK(JNIEnv *env, jobject thiz,
                                                            jbyteArray pem_file) {
    int len = env->GetArrayLength(pem_file);
    uint8_t *buf = new unsigned char[len];
    env->GetByteArrayRegion(pem_file, 0, len, reinterpret_cast<jbyte *>(buf));

    writeWalletKey(buf, len);


}

extern "C"
JNIEXPORT void JNICALL
Java_jni_DAAInterface_registerIssuerPK(JNIEnv *env, jobject thiz,
                                                            jbyteArray pem_file) {
    int len = env->GetArrayLength(pem_file);
    uint8_t *buf = new unsigned char[len];
    env->GetByteArrayRegion(pem_file, 0, len, reinterpret_cast<jbyte *>(buf));

    writeIssuerKey(buf, len);


}
extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_DAAIssuerRegistration(JNIEnv *env, jobject thiz,
                                                                 jbyteArray signedNonce
) {

    int nonceLen = env->GetArrayLength(signedNonce);
    uint8_t *signedNonce_C = new unsigned char[nonceLen];
    env->GetByteArrayRegion(signedNonce, 0, nonceLen, reinterpret_cast<jbyte *>(signedNonce_C));

    onNewSessionFromVCIssuer(&ek, signedNonce_C, nonceLen);

}

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_jni_DAAInterface_startDAASession(JNIEnv *env, jobject thiz) {
    TPM2B_NONCE nonce;
    requestNonce(&nonce);

    jbyteArray jNonce = env->NewByteArray(nonce.t.size);
    env->SetByteArrayRegion(jNonce, 0, nonce.t.size,
                            reinterpret_cast<const jbyte *>(nonce.t.buffer));
    return jNonce;
}


jstring marshalDAASignature(DAA_SIGNATURE* sig,JNIEnv *env){
    cJSON *root = NULL;
    root = cJSON_CreateObject();


    cJSON *signatureR = cJSON_CreateArray();
    cJSON *signatureS = cJSON_CreateArray();
    cJSON *V = cJSON_CreateArray();
    cJSON *rcre = cJSON_CreateObject();

    for (int i = 0; i < 32; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->signatureS[i]);
        cJSON_AddItemToArray(signatureS, byte);
    }
    for (int i = 0; i < 32; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->signatureR[i]);
        cJSON_AddItemToArray(signatureR, byte);
    }
    for (int i = 0; i < 32; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->V[i]);
        cJSON_AddItemToArray(V, byte);
    }

    cJSON *p1_x = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[0].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[0].x_coord[i]);
        cJSON_AddItemToArray(p1_x, byte);
    }

    cJSON *p1_y = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[0].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[0].y_coord[i]);
        cJSON_AddItemToArray(p1_y, byte);
    }

    cJSON *p2_x = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[1].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[1].x_coord[i]);
        cJSON_AddItemToArray(p2_x, byte);
    }

    cJSON *p2_y = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[1].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[1].y_coord[i]);
        cJSON_AddItemToArray(p2_y, byte);
    }

    cJSON *p3_x = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[2].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[2].x_coord[i]);
        cJSON_AddItemToArray(p3_x, byte);
    }

    cJSON *p3_y = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[2].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[2].y_coord[i]);
        cJSON_AddItemToArray(p3_y, byte);
    }

    cJSON *p4_x = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[3].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[3].x_coord[i]);
        cJSON_AddItemToArray(p4_x, byte);
    }

    cJSON *p4_y = cJSON_CreateArray();
    for (int i = 0; i < sig->rcre.points[3].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(sig->rcre.points[3].y_coord[i]);
        cJSON_AddItemToArray(p4_y, byte);
    }

    cJSON_AddItemToObject(root, "sigS", signatureS);
    cJSON_AddItemToObject(root, "sigR", signatureR);
    cJSON_AddItemToObject(root, "V", V);

    cJSON_AddItemToObject(rcre, "p1_x", p1_x);
    cJSON_AddItemToObject(rcre, "p1_y", p1_y);

    cJSON_AddItemToObject(rcre, "p2_x", p2_x);
    cJSON_AddItemToObject(rcre, "p2_y", p2_y);

    cJSON_AddItemToObject(rcre, "p3_x", p3_x);
    cJSON_AddItemToObject(rcre, "p3_y", p3_y);

    cJSON_AddItemToObject(rcre, "p4_x", p4_x);
    cJSON_AddItemToObject(rcre, "p4_y", p4_y);


    cJSON_AddItemToObject(root, "rcre", rcre);

    char *json = cJSON_PrintUnformatted(root);

    return env->NewStringUTF(json);

}

extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_DAASign(JNIEnv *env, jobject thiz, jbyteArray data,
                                                   jbyteArray signed_nonce) {

    int nonceLen = env->GetArrayLength(signed_nonce);
    uint8_t *signedNonce_C = new unsigned char[nonceLen];
    env->GetByteArrayRegion(signed_nonce, 0, nonceLen, reinterpret_cast<jbyte *>(signedNonce_C));

    int dataLen = env->GetArrayLength(data);
    uint8_t *dataBuf = new unsigned char[dataLen];
    env->GetByteArrayRegion(data, 0, dataLen, reinterpret_cast<jbyte *>(dataBuf));

    DAA_SIGNATURE sig = execute_daa_sign(dataBuf, dataLen, signedNonce_C, nonceLen);

    return  marshalDAASignature(&sig,env);
}


extern "C"
JNIEXPORT void JNICALL
Java_jni_DAAInterface_runFullDemo(JNIEnv *env, jobject thiz) {
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    LOGD("Hello, World!\n");


    //loadIssuerAuthorizationKey();
    TPM2B_PUBLIC ek = setup();

    // Act as wallet //
    TPM2B_NONCE nonce;

    uint8_t nonce_digest[SHA256_DIGEST_SIZE];
    uint8_t nonce_sig[150];
    LOGD("\n[ \t Wallet Requesting & Signing Nonce \t]\n");

    requestNonce(&nonce);
    clock_t t;
    t = clock();
    int len = wallet_sign_nonce(&nonce, nonce_digest, "/sdcard/Documents/TPM/Keys/wallet/key.pem",
                                nonce_sig);


    LOGD("\n[ \t Bridge Informed to Create New Attestation Key \t]\n");
    onNewSessionFromVCIssuer(&ek, nonce_sig, len);


    LOGD("\n[ \t Wallet Signs Nonce to Authorize a Sign Operation\t]\n");

    requestNonce(&nonce);
    len = wallet_sign_nonce(&nonce, nonce_digest, "/sdcard/Documents/TPM/Keys/wallet/key.pem",
                            nonce_sig);

    uint8_t msg[10];
    RAND_bytes(msg, 10);


    execute_daa_sign(msg, 10, nonce_sig, len);

    //  onCreateAttestationKeyCommand(&iss_pk);

    finalizeContext();

}
extern "C"
JNIEXPORT void JNICALL
Java_jni_DAAInterface_registerIssuer_1priv(JNIEnv *env, jobject thiz,
                                                                jbyteArray pem_file) {
    int len = env->GetArrayLength(pem_file);
    uint8_t *buf = new unsigned char[len];
    env->GetByteArrayRegion(pem_file, 0, len, reinterpret_cast<jbyte *>(buf));
    writeIssuerPrivKey(buf, len);
}
extern "C"
JNIEXPORT void JNICALL
Java_jni_DAAInterface_registerWallet_1priv(JNIEnv *env, jobject thiz,
                                                                jbyteArray pem_file) {
    int len = env->GetArrayLength(pem_file);
    uint8_t *buf = new unsigned char[len];
    env->GetByteArrayRegion(pem_file, 0, len, reinterpret_cast<jbyte *>(buf));
    writeWalletPrivKey(buf, len);
}


int
buildRegistrationInformation(TPM2B_NONCE *nonce, TPM2B_PUBLIC *endorsementKey, char *bufferOut) {
    cJSON *root = NULL;
    root = cJSON_CreateObject();
    uint16_t written = 0;
    uint8_t *buffer = NULL;
    TSS_Structure_Marshal(&buffer, &written, endorsementKey,
                          (MarshalFunction_t) TSS_TPM2B_PUBLIC_Marshalu);


    cJSON *nonceArr = cJSON_CreateArray();
    for (int i = 0; i < nonce->t.size; i++) {
        cJSON *byte = cJSON_CreateNumber(nonce->t.buffer[i]);
        cJSON_AddItemToArray(nonceArr, byte);
    }
    cJSON *ekArr = cJSON_CreateArray();
    for (int i = 0; i < written; i++) {
        cJSON *byte = cJSON_CreateNumber(buffer[i]);
        cJSON_AddItemToArray(ekArr, byte);
    }


    cJSON_AddItemToObject(root, "nonce", nonceArr);
    cJSON_AddItemToObject(root, "endorsementKey", ekArr);

    char *json = cJSON_PrintUnformatted(root);
    memcpy(bufferOut, json, strlen(json));
    free(buffer);

    return strlen(json);

}

int buildIssuerRegistrationPackage(TPMT_PUBLIC *ak, TPM2B_PUBLIC *endorsementKey, char *bufferOut) {
    cJSON *root = NULL;
    root = cJSON_CreateObject();
    uint16_t written = 0;
    uint8_t *buffer = NULL;
    TPM_RC rc;
    rc = TSS_Structure_Marshal(&buffer, &written, ak, (MarshalFunction_t) TSS_TPMT_PUBLIC_Marshalu);


    cJSON *akArr = cJSON_CreateArray();
    for (int i = 0; i < written; i++) {
        cJSON *byte = cJSON_CreateNumber(buffer[i]);
        cJSON_AddItemToArray(akArr, byte);
    }

    cJSON_AddItemToObject(root, "daaKey", akArr);

    cJSON *ekArr = cJSON_CreateArray();
    uint8_t *buffer2 = NULL;
    written = 0;
    rc = TSS_Structure_Marshal(&buffer2, &written, endorsementKey,
                               (MarshalFunction_t) TSS_TPM2B_PUBLIC_Marshalu);
    for (int i = 0; i < written; i++) {
        cJSON *byte = cJSON_CreateNumber(buffer2[i]);
        cJSON_AddItemToArray(ekArr, byte);
    }
    cJSON_AddItemToObject(root, "endorsementKey", ekArr);


    char *json = cJSON_PrintUnformatted(root);
    LOGD("Issuer Registration Package: %s\n", json);
    LOGD("Length: %zu\n", strlen(json));
    memcpy(bufferOut, json, strlen(json));
    free(buffer);

    return strlen(json);
}

// ISSUER TEST
TPM2B_NONCE parseNonce(const char *data) {
    cJSON *root = cJSON_Parse(data);
    cJSON *nonce = cJSON_GetObjectItem(root, "nonce");
    cJSON *iterator = NULL;

    unsigned char n[100];
    int i = 0;
    cJSON_ArrayForEach(iterator, nonce) {
        if (cJSON_IsNumber(iterator)) {
            n[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    TPM2B_NONCE nS;
    nS.t.size = i;
    memcpy(nS.t.buffer, n, i);
    return nS;
}

extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_DAAEnable(JNIEnv *env, jobject thiz) {

    // Get EndorsementKey
    ek = setup();

    // Get Nonce
    TPM2B_NONCE nonce;
    requestNonce(&nonce);

    // Build object
    int size = buildRegistrationInformation(&nonce, &ek, jsonBuffer);

    // Returns as string
    return (*env).NewStringUTF(jsonBuffer);
}
extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_CreateEnableResponse(JNIEnv *env, jobject thiz,
                                                                jbyteArray signedNonce) {

    int nonceLen = env->GetArrayLength(signedNonce);
    uint8_t *signedNonce_C = new unsigned char[nonceLen];
    env->GetByteArrayRegion(signedNonce, 0, nonceLen, reinterpret_cast<jbyte *>(signedNonce_C));

    // We assume that the bridge have set the IssuerPublicKey now
    TPM2B_PUBLIC issPk;
    convertEcPemToPublic(&issPk, TYPE_SI, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA256,
                         "/sdcard/Documents/TPM/IS.pem");

    // Create attestationKey
    TPMT_PUBLIC ak = onCreateAttestationKeyCommand(&issPk, signedNonce_C, nonceLen);

    // Build object
    memset(jsonBuffer, 0, 4000);
    int size = buildIssuerRegistrationPackage(&ak, &ek, jsonBuffer);
    LOGD("Size of registration package: %d\n", size);
    return (*env).NewStringUTF(jsonBuffer);


}


AUTHORIZATION parseAuth(const char *json, char *name) {
    cJSON *root = cJSON_Parse(json);
    cJSON *authMain = cJSON_GetObjectItem(root, name);

    cJSON *signature = cJSON_GetObjectItem(authMain, "signature");
    cJSON *digest = cJSON_GetObjectItem(authMain, "digest");
    cJSON *approvedPolicy = cJSON_GetObjectItem(authMain, "approvedPolicy");

    cJSON *iterator = NULL;
    AUTHORIZATION auth;

    auth.sigLen = 0;
    cJSON_ArrayForEach(iterator, signature) {
        if (cJSON_IsNumber(iterator)) {
            auth.signature[auth.sigLen++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    int i = 0;
    cJSON_ArrayForEach(iterator, digest) {
        if (cJSON_IsNumber(iterator)) {
            auth.digest[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    i = 0;
    cJSON_ArrayForEach(iterator, approvedPolicy) {
        if (cJSON_IsNumber(iterator)) {
            auth.approvedPolicy[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    cJSON_Delete(root);
    return auth;
}

CHALLENGE_CREDENTIAL parseChallengeJson(const char *json) {
    cJSON *root = cJSON_Parse(json);
    cJSON *challengeCredential = cJSON_GetObjectItem(root, "challengeCredential");

    cJSON *secret = cJSON_GetObjectItem(challengeCredential, "secret");
    cJSON *credential = cJSON_GetObjectItem(challengeCredential, "credential");

    cJSON *iterator = NULL;
    CHALLENGE_CREDENTIAL ccre;

    ccre.credential_length = 0;
    ccre.secret_length = 0;

    cJSON_ArrayForEach(iterator, credential) {
        if (cJSON_IsNumber(iterator)) {
            ccre.credential[ccre.credential_length++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    cJSON_ArrayForEach(iterator, secret) {
        if (cJSON_IsNumber(iterator)) {
            ccre.secret[ccre.secret_length++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }


    cJSON_Delete(root);
    return ccre;

}

TPML_PCR_SELECTION getPCRSelection_temp(int num, ...) {
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

TPML_PCR_SELECTION parsePCR(const char *json) {
    cJSON *root = cJSON_Parse(json);
    cJSON *pcr = cJSON_GetObjectItem(root, "pcrSelection");

    cJSON *iterator = NULL;
    uint8_t pcrMarshaled[500];
    TPML_PCR_SELECTION pcrSelection;

    int i = 0;
    cJSON_ArrayForEach(iterator, pcr) {
        if (cJSON_IsNumber(iterator)) {
            pcrMarshaled[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    BYTE *pPtr = pcrMarshaled;
    uint32_t size = 10;
    int derp = TSS_TPML_PCR_SELECTION_Unmarshalu(&pcrSelection, &pPtr, &size); // Todo test

    LOGD("Unmarshal: %d\n", derp);

    //TODO: FIX TPML_PCR

    return getPCRSelection_temp(2, 1, 12);

}


int buildChallengeResponse(CHALLENGE_RESPONSE cr, char *bufferOut) {
    cJSON *root = NULL;
    cJSON *daaSig = NULL;

    root = cJSON_CreateObject();
    daaSig = cJSON_CreateObject();
    cJSON *rcre = cJSON_CreateObject();



    // Credential Key
    cJSON *credentialKey = cJSON_CreateArray();
    for (int i = 0; i < cr.certLen; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.credneitalKey[i]);
        cJSON_AddItemToArray(credentialKey, byte);
    }
    cJSON_AddItemToObject(root, "credentialKey", credentialKey);

    cJSON *p1_x = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[0].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[0].x_coord[i]);
        cJSON_AddItemToArray(p1_x, byte);
    }

    cJSON *p1_y = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[0].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[0].y_coord[i]);
        cJSON_AddItemToArray(p1_y, byte);
    }

    cJSON *p2_x = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[1].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[1].x_coord[i]);
        cJSON_AddItemToArray(p2_x, byte);
    }

    cJSON *p2_y = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[1].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[1].y_coord[i]);
        cJSON_AddItemToArray(p2_y, byte);
    }

    cJSON *p3_x = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[2].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[2].x_coord[i]);
        cJSON_AddItemToArray(p3_x, byte);
    }

    cJSON *p3_y = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[2].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[2].y_coord[i]);
        cJSON_AddItemToArray(p3_y, byte);
    }

    cJSON *p4_x = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[3].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[3].x_coord[i]);
        cJSON_AddItemToArray(p4_x, byte);
    }

    cJSON *p4_y = cJSON_CreateArray();
    for (int i = 0; i < cr.sig.rcre.points[3].coord_len; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.rcre.points[3].y_coord[i]);
        cJSON_AddItemToArray(p4_y, byte);
    }

    cJSON *sigS = cJSON_CreateArray();
    for (int i = 0; i < 32; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.signatureS[i]);
        cJSON_AddItemToArray(sigS, byte);
    }

    cJSON *sigR = cJSON_CreateArray();
    for (int i = 0; i < 32; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.signatureR[i]);
        cJSON_AddItemToArray(sigR, byte);
    }

    cJSON *V = cJSON_CreateArray();
    for (int i = 0; i < 32; i++) {
        cJSON *byte = cJSON_CreateNumber(cr.sig.V[i]);
        cJSON_AddItemToArray(V, byte);
    }

    cJSON_AddItemToObject(rcre, "p1_x", p1_x);
    cJSON_AddItemToObject(rcre, "p1_y", p1_y);

    cJSON_AddItemToObject(rcre, "p2_x", p2_x);
    cJSON_AddItemToObject(rcre, "p2_y", p2_y);

    cJSON_AddItemToObject(rcre, "p3_x", p3_x);
    cJSON_AddItemToObject(rcre, "p3_y", p3_y);

    cJSON_AddItemToObject(rcre, "p4_x", p4_x);
    cJSON_AddItemToObject(rcre, "p4_y", p4_y);


    cJSON_AddItemToObject(daaSig, "sigS", sigS);
    cJSON_AddItemToObject(daaSig, "sigR", sigR);

    cJSON_AddItemToObject(daaSig, "V", V);
    cJSON_AddItemToObject(daaSig, "daa_credential", rcre);
    cJSON_AddItemToObject(root, "daaSignature", daaSig);

    char *json = cJSON_PrintUnformatted(root);
    memcpy(bufferOut, json, strlen(json));

    cJSON_Delete(root);

    return strlen(json);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_HandleIssuerChallenge(JNIEnv *env, jobject thiz,
                                                                 jstring issuerChallenge) {
    // TODO: implement HandleIssuerChallenge()

    const char *json = env->GetStringUTFChars(issuerChallenge, 0);

    CHALLENGE_CREDENTIAL ccre = parseChallengeJson(json);
    AUTHORIZATION sigAuth = parseAuth(json, "signAuthorization");
    AUTHORIZATION comAuth = parseAuth(json, "commitAuthorization");
    TPML_PCR_SELECTION pcr = parsePCR(json);

    CHALLENGE_RESPONSE cr = onIssuerChallenge(ccre, sigAuth, comAuth, pcr);

    memset(jsonBuffer, 0, 4000);
    buildChallengeResponse(cr, jsonBuffer);
    return (*env).NewStringUTF(jsonBuffer);


}


FULL_CREDENTIAL parseFullCredential(const char *json) {

    cJSON *root = cJSON_Parse(json);
    cJSON *encryptedCredential = cJSON_GetObjectItem(root, "encryptedCredential");
    cJSON *joinCredential = cJSON_GetObjectItem(root, "joinCredential");

    cJSON *secret = cJSON_GetObjectItem(joinCredential, "secret");
    cJSON *credential = cJSON_GetObjectItem(joinCredential, "credential");

    cJSON *iterator = NULL;
    FULL_CREDENTIAL fcre;

    fcre.join_credential.credential_length = 0;
    fcre.join_credential.secret_length = 0;
    fcre.encryptedLength = 0;
    cJSON_ArrayForEach(iterator, credential) {
        if (cJSON_IsNumber(iterator)) {
            fcre.join_credential.credential[fcre.join_credential.credential_length++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    cJSON_ArrayForEach(iterator, secret) {
        if (cJSON_IsNumber(iterator)) {
            fcre.join_credential.secret[fcre.join_credential.secret_length++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    cJSON_ArrayForEach(iterator, encryptedCredential) {
        if (cJSON_IsNumber(iterator)) {
            fcre.credentialEncrypted[fcre.encryptedLength++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }

    cJSON_Delete(root);
    return fcre;

}

extern "C"
JNIEXPORT void JNICALL
Java_jni_DAAInterface_EnableDAACredential(JNIEnv *env, jobject thiz,
                                                               jstring fullcre) {
    FULL_CREDENTIAL fcre = parseFullCredential(env->GetStringUTFChars(fullcre, 0));
    onIssuerFCRE(fcre);
    LOGD("Credential Activated :D");
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_jni_DAAInterface_prepareEnableResponse(JNIEnv *env, jobject thiz,
                                                                 jstring json) {

    const char *data = env->GetStringUTFChars(json, 0);
    LOGD("Got nonce raw: %s\n", data);

    // Get the nonce
    TPM2B_NONCE n = parseNonce(data);
    uint8_t nonce_digest[SHA256_DIGEST_SIZE];
    uint8_t nonce_sig[150];
    LOGD("\n[ \t Wallet Requesting & Signing Nonce \t]\n");

    int len = wallet_sign_nonce(&n, nonce_digest, "/sdcard/Documents/TPM/Keys/wallet/key.pem",
                                nonce_sig);

    jbyteArray jNonce = env->NewByteArray(len);
    env->SetByteArrayRegion(jNonce, 0, len,
                            reinterpret_cast<const jbyte *>(nonce_sig));

    return jNonce;
}
extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_getIssuerChallenge(JNIEnv *env, jobject thiz,
                                                              jstring json_nonce_and_ek) {

    const char *issuer_challenge = send_issuer_registration(
            env->GetStringUTFChars(json_nonce_and_ek, 0));

    jstring challenge = (*env).NewStringUTF(issuer_challenge);
    free((void *) issuer_challenge);
    return challenge;

}
extern "C"
JNIEXPORT jstring JNICALL
Java_jni_DAAInterface_sendChallengeResponse(JNIEnv *env, jobject thiz,
                                                                 jstring cr) {
    return (*env).NewStringUTF(send_challenge_response(env->GetStringUTFChars(cr, 0)));
}
extern "C"
JNIEXPORT jbyteArray JNICALL
Java_jni_DAAInterface_walletDoMeASignPlz(JNIEnv *env, jobject thiz,
                                                              jbyteArray nonce) {
    int nonceLen = env->GetArrayLength(nonce);
    uint8_t *noncetosign = new unsigned char[nonceLen];
    env->GetByteArrayRegion(nonce, 0, nonceLen, reinterpret_cast<jbyte *>(noncetosign));

    TPM2B_NONCE n;
    memcpy(n.t.buffer,noncetosign,nonceLen);
    n.t.size = nonceLen;
    uint8_t nonce_digest[SHA256_DIGEST_SIZE];
    uint8_t nonce_sig[150];
    LOGD("\n[ \t Wallet Requesting & Signing Nonce \t]\n");

    int len = wallet_sign_nonce(&n, nonce_digest, "/sdcard/Documents/TPM/Keys/wallet/key.pem",
                                nonce_sig);

    jbyteArray jNonce = env->NewByteArray(len);
    env->SetByteArrayRegion(jNonce, 0, len,
                            reinterpret_cast<const jbyte *>(nonce_sig));

    return jNonce;

}

DAA_SIGNATURE unmarshalDAASignature(const char* signature){

    DAA_SIGNATURE daaSig;
    cJSON *root = cJSON_Parse(signature);
    cJSON *sigS = cJSON_GetObjectItem(root, "sigS");
    cJSON *sigR = cJSON_GetObjectItem(root, "sigR");
    cJSON *V = cJSON_GetObjectItem(root, "V");
    cJSON *rcre = cJSON_GetObjectItem(root, "rcre");
    cJSON *p1x = cJSON_GetObjectItem(rcre, "p1_x");
    cJSON *p1y = cJSON_GetObjectItem(rcre, "p1_y");
    cJSON *p2x = cJSON_GetObjectItem(rcre, "p2_x");
    cJSON *p2y = cJSON_GetObjectItem(rcre, "p2_y");
    cJSON *p3x = cJSON_GetObjectItem(rcre, "p3_x");
    cJSON *p3y = cJSON_GetObjectItem(rcre, "p3_y");
    cJSON *p4x = cJSON_GetObjectItem(rcre, "p4_x");
    cJSON *p4y = cJSON_GetObjectItem(rcre, "p4_y");



    cJSON *iterator = NULL;
    int i = 0;


    cJSON_ArrayForEach(iterator, sigS) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.signatureS[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    i = 0;

    cJSON_ArrayForEach(iterator, sigR) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.signatureR[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }
    i = 0;

    cJSON_ArrayForEach(iterator, V) {
        if (cJSON_IsNumber(iterator)) {
            daaSig.V[i++] = (uint8_t) iterator->valueint;
        } else {
            LOGD("invalid, ");
        }
    }


    i = 0;
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
    cJSON_Delete(root);

    return daaSig;


}


extern "C"
JNIEXPORT jint JNICALL
Java_jni_DAAInterface_verifySignature(JNIEnv *env, jobject thiz,
                                                             jstring json_signature,
                                                             jbyteArray message) {
    const char *json = env->GetStringUTFChars(json_signature, 0);
    int len = env->GetArrayLength(message);
    uint8_t *buf = new unsigned char[len];
    env->GetByteArrayRegion(message, 0, len, reinterpret_cast<jbyte *>(buf));

    DAA_SIGNATURE sig = unmarshalDAASignature(json);
    if(verifyDAASignature(buf,len,&sig) == RC_OK) return 1;
    return 0;
}
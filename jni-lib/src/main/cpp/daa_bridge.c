//
// Created by benlar on 1/4/22.
//

#include "Test_issuer/issuer_interface.h"
#include "daa/daa_issuer.h"
#include "daa_bridge.h"
#include "persistence.h"
#include "defines.h"
#include "memory.h"
#include "policy.h"
#include "daa/daa_client_base.h"
#include "bridge_tpm.h"
#include "templates.h"
#include "cryptoutils.h"
#include "objecttemplates.h"

#define  LOG_TAG    "DAA-BRIDGE"

#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)


// Keys
PRIMARY_KEY ek_key;
PRIMARY_KEY daa_key_p;
const char *walletKeyPath = "/sdcard/Documents/TPM/WK.pem";
const char *issuerKeyPath = "/sdcard/Documents/TPM/IS.pem";

const char *issuerPrivKeyPath = "/sdcard/Documents/TPM/IS_priv.pem";
const char *walletPrivKeyPath = "/sdcard/Documents/TPM/WK_priv.pem";


SIGNATURE_VERIFICATION auth_ticket;
SIGNATURE_VERIFICATION commit_ticket;
AUTHORIZATION sign_auth;
AUTHORIZATION commit_auth;
TPM_HANDLE signSession;
uint8_t nonce_sig[150];
uint8_t nonce_len;
TPM2B_NONCE signNonce;
TPM2B_NAME issName;
DAA_CREDENTIAL credential;
TPML_PCR_SELECTION pcrSelection;
TPM2B_PUBLIC daaTemplate;


void load_wallet_key(TPM2B_PUBLIC *wkPub) {
    convertEcPemToPublic(wkPub, TYPE_SI, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA256,
                         walletKeyPath);

}

void load_is_key(TPM2B_PUBLIC *wkPub) {
    convertEcPemToPublic(wkPub, TYPE_SI, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA256,
                         "/sdcard/Documents/TPM/Keys/public.pem");

}

void getNameFromKey(TPM2B_PUBLIC *publicKey, unsigned char *nameOut) {
    TPM2B_TEMPLATE marshaled;
    TPMT_HA name;
    uint16_t written;
    uint32_t size;
    uint8_t *buffer;

    name.hashAlg = publicKey->publicArea.nameAlg;

    written = 0;
    size = sizeof(marshaled.t.buffer);
    buffer = marshaled.t.buffer;

    int rc = TSS_TPMT_PUBLIC_Marshalu(&publicKey->publicArea, &written, &buffer, &size);
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

/*
 * Function:  defineAttestationKeyPolicy
 * --------------------
 * Computes TPM Policy Digest for PolicyAuthorize (PolicyPCR && PolicySigned)
 *
 */
void defineAttestationKeyPolicy(TPM2B_PUBLIC *issuerPK, uint8_t *policyDigestOut) {

    uint8_t iss_name[DIGEST_SIZE + 2];
    // Ensure policyDigestOut is zeroes
    memset(policyDigestOut, 0, DIGEST_SIZE);

    getNameFromKey(issuerPK, iss_name);
    updatePolicyAuthorize(iss_name, DIGEST_SIZE + 2, policyDigestOut);

    /*
    // Begin by updating with PolicySigned
    updatePolicySigned(wallet_key_name, name_len, policyDigestOut);

    // Update with PolicyPCR
    updatePolicyPCR(pcr_selection, expected_state_digest, policyDigestOut);
     */

}


void create_DAA_key(uint8_t *policy, PRIMARY_KEY *keyOut) {

    // We assume EK is already loaded?
    // TODO: check
    LOGD("[ \t Bridge Creates Key \t]\n");

    // Convert policy to TPM2B
    TPM2B_DIGEST policyDigest;
    TSS_TPM2B_Create(&policyDigest.b, policy, DIGEST_SIZE, DIGEST_SIZE);

    buildDAAKeyTemplate(&daaTemplate, &policyDigest);

    // Create the key
    tpm2_createPrimary(&daaTemplate, TPM_RH_ENDORSEMENT, keyOut);

}

TPMT_PUBLIC
onCreateAttestationKeyCommand(TPM2B_PUBLIC *issuer_pub, uint8_t *signedNonce, int nonceLen) {

    uint8_t policyDigest[DIGEST_SIZE];
    uint8_t manifestDigest[DIGEST_SIZE];

    // Persist Issuer Public Key: //TODO
    /*  if (issuer_pub != NULL)
          persist_key(ISSUER_KEY, issuer_pub, key_len);*/

    // Request manifest digest
    request_manifest_digest(manifestDigest);
    memcpy(nonce_sig, signedNonce, nonceLen);
    nonce_len = nonceLen;

    // Define a Policy Digest
    KEY walletKey = request_key(WALLET_KEY);
    LOGD("[ \t Bridge Calculated Policy (PolicyAuthorize by Issuer) \t]\n");
    defineAttestationKeyPolicy(issuer_pub, policyDigest);

    // Create a get certificate
    create_DAA_key(policyDigest, &daa_key_p);
    DOOR_ISSUER_REGISTRATION reg;
    reg.akPub = daa_key_p.outPublic.publicArea;
    //  memset(reg.name, 0, NAME_LEN);


    return daa_key_p.outPublic.publicArea;
    // Issuer contact
    //   send_issuer_registration(&reg);

    // Return

}

// Runs setup to ensure all is ready
TPM2B_PUBLIC setup() {
    LOGD("[ \t Initializing System Setup \t]\n");
    initializeTPM(REBOOT); // Reboots only if SW TPM
    TPM2B_PUBLIC pk;
    // Create Endorsement
    TPM2B_PUBLIC ekTemplate;
    buildRSAKey(&ekTemplate, NULL);

    // Create the key
    tpm2_createPrimary(&ekTemplate, TPM_RH_ENDORSEMENT, &ek_key);

    LOGD("Evicting Control...\n");

    // Evict it to NV-RAM
    if (tpm2_evictControl(ek_key.objectHandle, EK_PERSISTENT_HANDLE) != EXIT_SUCCESS) {
        LOGD("Evicting Control failed - already exists? Removing old one...\n");

        // Remove old one
        tpm2_evictControl(EK_PERSISTENT_HANDLE, EK_PERSISTENT_HANDLE);
        LOGD("Inserting new one...\n");

        // Add the new one
        if (tpm2_evictControl(ek_key.objectHandle, EK_PERSISTENT_HANDLE) != EXIT_SUCCESS) {
            LOGD("Sumting wong...\n");

            LOGD("HUUUUUUUUUUUUUUUUUUUGE ERROR\n");
            //exit(NV_ERROR);
        }
    }

    pk = ek_key.outPublic;
    // Flush the old handle
    tpm2_flushContext(ek_key.objectHandle);

    return pk;


}


void satisfyPolicy(TPML_PCR_SELECTION *sel, TPM_HANDLE sess) {

    TPM2B_PUBLIC wallet_public;
    TPM2B_PUBLIC is_public;

    load_wallet_key(&wallet_public);
    load_is_key(&is_public);

    TPM_HANDLE wallet_handle;

    tpm2_loadExternal(&wallet_public, TPM_RH_ENDORSEMENT, &wallet_handle);

    TPMT_SIGNATURE sig;
    convertEcBinToTSignature(&sig, HASH_ALG, nonce_sig, nonce_len);

    tpm2_policySigned(wallet_handle, sess, &sig, &signNonce);
    tpm2_policyPCR(sess, sel);
    tpm2_flushContext(wallet_handle);


    TPM2B_DIGEST expected;
    memcpy(expected.t.buffer, sign_auth.approvedPolicy, DIGEST_SIZE);
    expected.t.size = DIGEST_SIZE;

    TPM2B_NAME signName;
    memcpy(signName.t.name, issName.t.name, NAME_LEN);
    signName.t.size = NAME_LEN;

    tpm2_policyAuthorize(signSession, &auth_ticket.validation, &signName, &expected);


}

void onIssuerFCRE(FULL_CREDENTIAL fcre) {
    unsigned char ck2[16];

    DAA_CONTEXT *ctx = new_daa_context();
    int certLen;
    tpm2_activateCredential(daa_key_p.objectHandle, EK_PERSISTENT_HANDLE, &fcre.join_credential,
                            ck2, &certLen);

    if (daa_decrypt_credential_data(ctx, fcre.credentialEncrypted, fcre.encryptedLength, ck2,
                                    &credential) != RC_OK) {
        LOGD("[-] Error in decrypting certificate\n");
    }

    tpm2_flushContext(daa_key_p.objectHandle);

    hash_begin(HASH_ALG);
    hash_update(credential.points[0].x_coord, EC_POINT_MAX_LEN);
    hash_update(credential.points[0].y_coord, EC_POINT_MAX_LEN);
    hash_update(credential.points[1].x_coord, EC_POINT_MAX_LEN);
    hash_update(credential.points[1].y_coord, EC_POINT_MAX_LEN);
    hash_update(credential.points[2].x_coord, EC_POINT_MAX_LEN);
    hash_update(credential.points[2].y_coord, EC_POINT_MAX_LEN);
    hash_update(credential.points[3].x_coord, EC_POINT_MAX_LEN);
    hash_update(credential.points[3].y_coord, EC_POINT_MAX_LEN);
    hash_final(credentialDigest);

    free_daa_context(ctx);

}

CHALLENGE_RESPONSE onIssuerChallenge(CHALLENGE_CREDENTIAL challenge, AUTHORIZATION signAuth,
                                     AUTHORIZATION commit_authIn,
                                     TPML_PCR_SELECTION pcr) {

    // Step 1: Load the Isser public (auhtorization) key.
    TPM2B_PUBLIC issAPK;
    TPM_HANDLE issHandle;
    CHALLENGE_RESPONSE cr;

    for (int i = 0; i < 4; i++) {
        cr.sig.rcre.points[i].coord_len = 0;
    }


    commit_auth = commit_authIn;

    // TODO: Cache?
    convertEcPemToPublic(&issAPK, TYPE_SI, TPM_ALG_ECDSA, TPM_ALG_SHA256, TPM_ALG_SHA256,
                         issuerKeyPath);


    LoadExternal_Out ldIs = tpm2_loadExternal(&issAPK, TPM_RH_ENDORSEMENT, &issHandle);
    issName = ldIs.name;
    sign_auth = signAuth;

    // Step 2: Verify the signature to obtain a ticket
    auth_ticket = tpm2_verifySignature(issHandle, signAuth.digest, DIGEST_SIZE,
                                       signAuth.signature,
                                       signAuth.sigLen);

    commit_ticket = tpm2_verifySignature(issHandle, commit_auth.digest, DIGEST_SIZE,
                                         commit_auth.signature, commit_auth.sigLen);


    // Step 3: Remove Iss key
    tpm2_flushContext(issHandle);

    // Step 4: Get credential key
    DAA_CONTEXT *ctx = new_daa_context();
    tpm2_activateCredential(daa_key_p.objectHandle, EK_PERSISTENT_HANDLE, &challenge,
                            cr.credneitalKey, &cr.certLen);

    // Commit
    COMMIT_DATA cd;

    TPM_HANDLE session;

    LOGD("\n[ \t Bridge Satisfies Authorized Policy (CommandCode & Commit) to Commit\t]\n");
    tpm2_startAuthSession(TPM_SE_POLICY, &session, NULL);

    tpm2_policyCommandCode(session, TPM_CC_Commit);
    TPM2B_DIGEST expected;
    memcpy(expected.t.buffer, commit_auth.approvedPolicy, DIGEST_SIZE);
    expected.t.size = DIGEST_SIZE;

    tpm2_policyAuthorize(session, &commit_ticket.validation, &ldIs.name, &expected);
    tpm2_commit(daa_key_p.objectHandle, NULL, session, NULL, NULL,
                &cd); // Automatically flush session



    // Prepare host
    unsigned char host_str[SHA256_DIGEST_SIZE];

    ECC_POINT daaPoint;
    memcpy(daaPoint.x_coord, daa_key_p.outPublic.publicArea.unique.ecc.x.t.buffer,
           daa_key_p.outPublic.publicArea.unique.ecc.x.t.size);
    memcpy(daaPoint.y_coord, daa_key_p.outPublic.publicArea.unique.ecc.y.t.buffer,
           daa_key_p.outPublic.publicArea.unique.ecc.y.t.size);
    daaPoint.coord_len = daa_key_p.outPublic.publicArea.unique.ecc.x.t.size;

    ECC_POINT commit_data_daa;
    memcpy(commit_data_daa.x_coord, cd.E.point.x.t.buffer, cd.E.point.x.t.size);
    memcpy(commit_data_daa.y_coord, cd.E.point.y.t.buffer, cd.E.point.y.t.size);
    commit_data_daa.coord_len = cd.E.point.x.t.size;
    daa_prepare_host_str(ctx, &daaPoint, &commit_data_daa, cr.credneitalKey,
                         ek_key.outPublic.publicArea.unique.rsa.t.buffer,
                         host_str);


    TPM_HASH host_string_digest;
    TPM2B_MAX_BUFFER host_str_in;
    memcpy(host_str_in.t.buffer, host_str, SHA256_DIGEST_SIZE);
    host_str_in.t.size = SHA256_DIGEST_SIZE;

    tpm2_hash(&host_str_in, TPM_RH_ENDORSEMENT, &host_string_digest);

    TPMT_SIG_SCHEME inScheme;
    // Now we can sign it with the DAA Key
    inScheme.scheme = TPM_ALG_ECDAA;
    inScheme.details.ecdaa.count = cd.counter;
    inScheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;

    // Satisfy Policy PolicySigned && PolicyPCR
    pcrSelection = pcr;
    LOGD("\n[ \t Bridge Satisfies Authorized Policy (PCR & Wallet Sign) to Sign\t]\n");

    satisfyPolicy(&pcr, signSession);


    TPMT_SIGNATURE sig_daa;
    tpm2_sign(daa_key_p.objectHandle, &signSession, &inScheme, &host_string_digest,
              &sig_daa); // Flushes session


    memcpy(cr.sig.signatureR, sig_daa.signature.ecdaa.signatureR.t.buffer,
           sig_daa.signature.ecdaa.signatureR.t.size);
    LOGD("SigR size: %d", sig_daa.signature.ecdaa.signatureR.t.size);
    LOGD("SigS size: %d", sig_daa.signature.ecdaa.signatureS.t.size);

    memcpy(cr.sig.signatureS, sig_daa.signature.ecdaa.signatureS.t.buffer,
           sig_daa.signature.ecdaa.signatureS.t.size);

    daa_finalize_credential_signature(ctx, &cr.sig, host_string_digest.outHash.t.buffer);


//    FULL_CREDENTIAL fcre = daa_on_host_response(ctx, cr.credneitalKey, &cr.sig, 1);

    return cr;



    // onIssuerFCRE(fcre);

    free_daa_context(ctx);


    /* // Sign?
     unsigned char buff[2];
     buff[0] = 0x02;
     buff[1] = 0x03;


     COMMIT_INFORMATION ci;
     COMMIT_DATA sign_cd;
     DAA_CREDENTIAL rcre = daa_prepare_commit(ctx, credential, &ci);

     TPM2B_ECC_POINT p1;
     memcpy(p1.point.x.t.buffer, ci.p1.x_coord, ci.p1.coord_len);
     memcpy(p1.point.y.t.buffer, ci.p1.y_coord, ci.p1.coord_len);
     p1.point.x.t.size = ci.p1.coord_len;
     p1.point.y.t.size = ci.p1.coord_len;

     TPM2B_SENSITIVE_DATA sense;
     memcpy(sense.t.buffer, ci.secret, ci.secretLen);


     tpm2_startAuthSession(TPM_SE_POLICY, &session, NULL);

     tpm2_policyCommandCode(session, TPM_CC_Commit);
     memcpy(expected.t.buffer, commit_auth.approvedPolicy, DIGEST_SIZE);
     expected.t.size = DIGEST_SIZE;

     tpm2_policyAuthorize(session, &commit_ticket.validation, &ldIs.name, &expected);


     tpm2_commit(daa_key_p.objectHandle, &p1, &session, NULL, NULL, &sign_cd);

     tpm2_flushContext(session);
     COMMIT_RESPONSE commitResponse;

     memcpy(commitResponse.E.x_coord, sign_cd.E.point.x.t.buffer, sign_cd.E.point.x.t.size);
     memcpy(commitResponse.E.y_coord, sign_cd.E.point.y.t.buffer, sign_cd.E.point.y.t.size);
     commitResponse.E.coord_len = sign_cd.E.point.y.t.size;


     memcpy(commitResponse.K.x_coord, sign_cd.K.point.x.t.buffer, sign_cd.K.point.x.t.size);
     memcpy(commitResponse.K.y_coord, sign_cd.K.point.y.t.buffer, sign_cd.K.point.y.t.size);
     commitResponse.K.coord_len = sign_cd.K.point.y.t.size;


     memcpy(commitResponse.L.x_coord, sign_cd.L.point.x.t.buffer, sign_cd.L.point.x.t.size);
     memcpy(commitResponse.L.y_coord, sign_cd.L.point.y.t.buffer, sign_cd.L.point.y.t.size);
     commitResponse.L.coord_len = sign_cd.L.point.y.t.size;

     commitResponse.counter = sign_cd.counter;


     TPM2B_MAX_BUFFER hBuff;
     hBuff.t.size = SHA256_DIGEST_SIZE;
     daa_prepare_hash(ctx, buff, 2, &rcre, &commitResponse, hBuff.t.buffer);

     TPM_HASH hOut;
     tpm2_hash(&hBuff, TPM_RH_ENDORSEMENT, &hOut);

     inScheme.scheme = TPM_ALG_ECDAA;
     inScheme.details.ecdaa.count = commitResponse.counter;
     inScheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;


     TPMT_SIGNATURE finalSIg;
     tpm2_sign(daa_key_p.objectHandle, &signSession, &inScheme, &hOut, &finalSIg);

     DAA_SIGNATURE dsig_final;
     tpm2_flushContext(signSession);

     memcpy(dsig_final.signatureS, finalSIg.signature.ecdaa.signatureS.t.buffer, 32);
     memcpy(dsig_final.signatureR, finalSIg.signature.ecdaa.signatureR.t.buffer, 32);

     daa_finalize_signature(ctx, &dsig_final, hOut.outHash.t.buffer);


     if (daa_verify_signature(ctx, buff, 2, &dsig_final, &rcre) == RC_OK) {
         LOGD("[+] Signature verified\n");
     } else {
         LOGD("Error in verification\n");
     }

 */
}

void requestNonce(TPM2B_NONCE *nonceOut) {

    tpm2_startAuthSession(TPM_SE_POLICY, &signSession, nonceOut);
    signNonce = *nonceOut;
}

DAA_SIGNATURE
execute_daa_sign(uint8_t *msg, size_t msgLen, uint8_t *signed_nonce, size_t signed_nonce_len) {

    // Step 1: Prepare DAA Signature
    tpm2_createPrimary(&daaTemplate, TPM_RH_ENDORSEMENT, &daa_key_p);
    COMMIT_INFORMATION ci;
    COMMIT_DATA sign_cd;
    TPM_HANDLE session;
    DAA_CONTEXT *ctx = new_daa_context();
    TPM2B_DIGEST expected;
    TPMT_SIG_SCHEME inScheme;

    memcpy(nonce_sig, signed_nonce, signed_nonce_len);
    nonce_len = signed_nonce_len;

    LOGD("\n[ \t Bridge Randomizes Credential & Satisfies Commit Policy \t]\n");
    DAA_CREDENTIAL rcre = daa_prepare_commit(ctx, credential, &ci);

    TPM2B_ECC_POINT p1;
    memcpy(p1.point.x.t.buffer, ci.p1.x_coord, ci.p1.coord_len);
    memcpy(p1.point.y.t.buffer, ci.p1.y_coord, ci.p1.coord_len);
    p1.point.x.t.size = ci.p1.coord_len;
    p1.point.y.t.size = ci.p1.coord_len;

    TPM2B_SENSITIVE_DATA sense;
    memcpy(sense.t.buffer, ci.secret, ci.secretLen);


    tpm2_startAuthSession(TPM_SE_POLICY, &session, NULL);

    tpm2_policyCommandCode(session, TPM_CC_Commit);
    memcpy(expected.t.buffer, commit_auth.approvedPolicy, DIGEST_SIZE);
    expected.t.size = DIGEST_SIZE;

    tpm2_policyAuthorize(session, &commit_ticket.validation, &issName, &expected);


    tpm2_commit(daa_key_p.objectHandle, &p1, session, NULL, NULL, &sign_cd); // Flushes session

    COMMIT_RESPONSE commitResponse;

    memcpy(commitResponse.E.x_coord, sign_cd.E.point.x.t.buffer, sign_cd.E.point.x.t.size);
    memcpy(commitResponse.E.y_coord, sign_cd.E.point.y.t.buffer, sign_cd.E.point.y.t.size);
    commitResponse.E.coord_len = sign_cd.E.point.y.t.size;


    memcpy(commitResponse.K.x_coord, sign_cd.K.point.x.t.buffer, sign_cd.K.point.x.t.size);
    memcpy(commitResponse.K.y_coord, sign_cd.K.point.y.t.buffer, sign_cd.K.point.y.t.size);
    commitResponse.K.coord_len = sign_cd.K.point.y.t.size;


    memcpy(commitResponse.L.x_coord, sign_cd.L.point.x.t.buffer, sign_cd.L.point.x.t.size);
    memcpy(commitResponse.L.y_coord, sign_cd.L.point.y.t.buffer, sign_cd.L.point.y.t.size);
    commitResponse.L.coord_len = sign_cd.L.point.y.t.size;

    commitResponse.counter = sign_cd.counter;


    TPM2B_MAX_BUFFER hBuff;
    hBuff.t.size = SHA256_DIGEST_SIZE;
    daa_prepare_hash(ctx, msg, msgLen, &rcre, &commitResponse, hBuff.t.buffer);

    TPM_HASH hOut;
    tpm2_hash(&hBuff, TPM_RH_ENDORSEMENT, &hOut);

    inScheme.scheme = TPM_ALG_ECDAA;
    inScheme.details.ecdaa.count = commitResponse.counter;
    inScheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;


    // Satisfy
    LOGD("\n[ \t Bridge Satisfies Sign Policy\t]\n");
    satisfyPolicy(&pcrSelection, signSession);

    TPMT_SIGNATURE finalSIg;
    tpm2_sign(daa_key_p.objectHandle, &signSession, &inScheme, &hOut, &finalSIg); // Flushes data


    DAA_SIGNATURE dsig_final;

    memcpy(dsig_final.signatureS, finalSIg.signature.ecdaa.signatureS.t.buffer, 32);
    memcpy(dsig_final.signatureR, finalSIg.signature.ecdaa.signatureR.t.buffer, 32);

    daa_finalize_signature(ctx, &dsig_final, hOut.outHash.t.buffer);

    dsig_final.rcre = rcre;

    LOGD("\n[ \t Verifier Verifies Signature\t]\n");
    if (daa_verify_signature(ctx, msg, msgLen, &dsig_final) == RC_OK) {
        LOGD("[+] Signature verified\n");
    } else {
        LOGD("Error in verification\n");
    }

    free_daa_context(ctx);

    return dsig_final;


}


void writeKeyIfNotExists(uint8_t *key, int keyLen, char *keyName) {
    int i;
    FILE *fptr;
    fptr = fopen(keyName, "w+"); // overwrites
    if (fptr == NULL) {
        LOGD("Can't Write Key\n");
    } else {
        LOGD("Key write to %s success\n", keyName);
    }
    for (i = 0; i < keyLen; i++) {
        fputc(key[i], fptr);
    }

    fclose(fptr);
}

void writeWalletKey(uint8_t *key, int keyLen) {
    writeKeyIfNotExists(key, keyLen, walletKeyPath);
}

void writeIssuerKey(uint8_t *key, int keyLen) {
    writeKeyIfNotExists(key, keyLen, issuerKeyPath);
}

void writeIssuerPrivKey(uint8_t *key, int keyLen) {
    writeKeyIfNotExists(key, keyLen, issuerPrivKeyPath);
}


void writeWalletPrivKey(uint8_t *key, int keyLen) {
    writeKeyIfNotExists(key, keyLen, walletPrivKeyPath);
}

int verifyDAASignature(uint8_t *message, size_t len, DAA_SIGNATURE *signature) {

    int res = 1;
    DAA_CONTEXT *ctx = new_daa_context();
    res = daa_verify_signature(ctx, message, len, signature);
    free_daa_context(ctx);
    return res;
}

//
// Created by benlar on 1/4/22.
//

//
// Created by benlar on 12/20/21.
//

#include "bridge_tpm.h"
#include "hash.h"
#include "defines.h"
#include "cryptoutils.h"
#include "objecttemplates.h"

#define VERBOSE
#define  LOG_TAG    "IBM-TPM"

#define  LOGD(...) DEBUG_PRINT(__VA_ARGS__)
#define  LOGE(...) DEBUG_PRINT(__VA_ARGS__)

TPM_RC rc = 0;
TSS_CONTEXT *ctx = NULL;


void handle_TPM_error(TPM_RC last_err, int isCritical) {
    const char *msg;
    const char *submsg;
    const char *num;
    TSS_ResponseCode_toString(&msg, &submsg, &num, last_err);

    if (last_err == TSS_RC_NO_CONNECTION) {
        LOGD("[-] An error occurred: %s (%s %s).\n", msg, submsg, num);
    }


    LOGD("[-] An error occurred: %s (%d) (%s %s).\n", msg, last_err, submsg, num);

    if (isCritical) {
        TSS_Delete(ctx);
        exit(-1);
    }

}


uint8_t tpm2_startAuthSession(TPMI_SH_POLICY sessionType, TPM_HANDLE *handleOut, TPM2B_NONCE *tpmNonce) {

    StartAuthSession_In in;
    StartAuthSession_Out out;
    StartAuthSession_Extra extra;

    if (handleOut == NULL) {
        LOGD("[-] Handle must not be null\n");
        return EXIT_FAILURE;
    }
#ifdef VERBOSE
    LOGD("[*] Starting new AuthSession of type %s\n",
           sessionType == TPM_SE_HMAC ? "HMAC" : (sessionType == TPM_SE_POLICY ? "Policy" : "Trial"));
#endif

    in.tpmKey = TPM_RH_NULL;
    in.encryptedSalt.b.size = 0;
    in.bind = TPM_RH_NULL;
    in.nonceCaller.t.size = 0;
    in.symmetric.algorithm = TPM_ALG_XOR;
    in.authHash = HASH_ALG;
    in.symmetric.keyBits.xorr = HASH_ALG;
    in.symmetric.mode.sym = TPM_ALG_NULL;
    extra.bindPassword = NULL;
    in.sessionType = sessionType;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     (EXTRA_PARAMETERS *) &extra,
                     TPM_CC_StartAuthSession,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

#ifdef VERBOSE
    LOGD("[+] Got handle %08x\n", out.sessionHandle);
#endif

    *handleOut = out.sessionHandle;

    if (tpmNonce != NULL)
        *tpmNonce = out.nonceTPM;

    return EXIT_SUCCESS;
}

int8_t initializeTPM(int reboot) {
    TSS_CONTEXT *localCtx;

#ifdef VERBOSE
    LOGD("[*] Initializing TPM - Creating TSS Context\n");
#endif

    rc = TSS_Create(&ctx);

    if (rc != TPM_RC_SUCCESS) handle_TPM_error(rc, CRITICAL);


#ifndef HWTPM
    if (reboot) {
#ifdef VERBOSE
        LOGD("[*] Running TPM Power Cycle on SW TPM\n");
#endif
        rc = TSS_Create(&localCtx);

        // If we are using a software TPM, we'll "start" the TPM.
        rc = TSS_TransmitPlatform(localCtx, TPM_SIGNAL_POWER_OFF, "TPM2_PowerOffPlatform");
        if (rc != TPM_RC_SUCCESS) handle_TPM_error(rc, CRITICAL);
        rc = TSS_TransmitPlatform(localCtx, TPM_SIGNAL_POWER_ON, "TPM2_PowerOnPlatform");
        if (rc != TPM_RC_SUCCESS) handle_TPM_error(rc, CRITICAL);
        rc = TSS_TransmitPlatform(localCtx, TPM_SIGNAL_NV_ON, "TPM2_NvOnPlatform");
        if (rc != TPM_RC_SUCCESS) handle_TPM_error(rc, CRITICAL);

        TSS_Delete(localCtx);
    }
#endif

    // Execute start command
    Startup_In in;
    in.startupType = TPM_SU_CLEAR;
    rc = TSS_Execute(ctx,
                     NULL,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_Startup,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) handle_TPM_error(rc, CRITICAL);

    return EXIT_SUCCESS;
}

void finalizeContext() {
    TSS_Delete(ctx);
}

uint8_t tpm2_flushContext(TPM_HANDLE handle) {

    FlushContext_In in;
    in.flushHandle = handle;

#ifdef VERBOSE
    LOGD("[*] Flushing handle %08x\n", handle);
#endif

    rc = TSS_Execute(ctx,
                     NULL,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_FlushContext,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        LOGD("[-] Flushing of handle %08x Error\n", handle);
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }


    return EXIT_SUCCESS;

}

uint8_t tpm2_create(TPM2B_PUBLIC *Keytemplate, TPM_HANDLE parent, TPML_PCR_SELECTION *pcrSelection,
                    const TPM_HANDLE *session, TPM_KEY *keyOut) {
    Create_In in;
    Create_Out out;


    TPMI_SH_AUTH_SESSION sessionHandle0 = session == NULL ? TPM_RS_PW : *session;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes0 = 0;
    unsigned int sessionAttributes1 = 0;
    unsigned int sessionAttributes2 = 0;


#ifdef VERBOSE
    LOGD("[*] Creating Key under key identified by handle %08x\n", parent);
#endif
    in.inPublic = *Keytemplate;
    in.parentHandle = parent;
    in.outsideInfo.t.size = 0;
    in.inSensitive.sensitive.data.t.size = 0;
    in.inSensitive.sensitive.userAuth.t.size = 0;
    if (pcrSelection != NULL)
        in.creationPCR = *pcrSelection;
    else in.creationPCR.count = 0;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_Create,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    *keyOut = out;

    return EXIT_SUCCESS;
}

uint8_t tpm2_createPrimary(TPM2B_PUBLIC *keytemplate, TPMI_RH_HIERARCHY hierarchy, PRIMARY_KEY *primaryKey) {
    CreatePrimary_In in;
    CreatePrimary_Out out;

    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    unsigned int sessionAttributes2 = 0;
    unsigned int sessionAttributes0 = 0;

#ifdef VERBOSE
    LOGD("[*] Creating primary key in %s hierarchy\n",
           hierarchy == TPM_RH_NULL ? "NULL" : (hierarchy == TPM_RH_OWNER ? "Owner" : (hierarchy == TPM_RH_PLATFORM
                                                                                       ? "Platform" : "Endorsement")));
#endif

    in.outsideInfo.t.size = 0;
    in.creationPCR.count = 0;
    in.primaryHandle = hierarchy;
    in.inSensitive.sensitive.data.t.size = 0;
    in.inSensitive.sensitive.userAuth.t.size = 0;
    in.inPublic = *keytemplate;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_CreatePrimary,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    *primaryKey = out;
#ifdef VERBOSE
    LOGD("[+] Key created with handle %08x\n", out.objectHandle);
#endif

    return EXIT_SUCCESS;
}

SIGNATURE_VERIFICATION tpm2_verifySignature(TPM_HANDLE key_handle, uint8_t* expected, int mdlen, uint8_t* sig, int siglen){
    VerifySignature_In in;
    VerifySignature_Out out;
    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
    unsigned int sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes2 = 0;

#ifdef VERBOSE
    LOGD("[*] Verifying signature\n");
#endif

    memcpy(in.digest.t.buffer,expected,mdlen);
    in.digest.t.size = mdlen;

    in.keyHandle = key_handle;
    convertEcBinToTSignature(&in.signature,HASH_ALG,sig,siglen);

    rc = TSS_Execute(ctx,
                           (RESPONSE_PARAMETERS *) &out,
                           (COMMAND_PARAMETERS *) &in,
                           NULL,
                           TPM_CC_VerifySignature,
                           sessionHandle0, NULL, sessionAttributes0,
                           sessionHandle1, NULL, sessionAttributes1,
                           sessionHandle2, NULL, sessionAttributes2,
                           TPM_RH_NULL, NULL, 0);

#ifdef VERBOSE
    if(rc == 0){
        LOGD("[+] Signature verified\n");
    }
    else{
        LOGD("[-] Signature failed to verify\n");
    }
#endif

    return out;

}

uint8_t tpm2_load(TPM_KEY *key, TPM_HANDLE parent, LOADED_KEY *outLoaded) {
    Load_In in;
    Load_Out out;

    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;

    unsigned int sessionAttributes0 = 0;
    unsigned int sessionAttributes1 = 0;
    unsigned int sessionAttributes2 = 0;

    in.inPublic = key->outPublic;
    in.inPrivate = key->outPrivate;
    in.parentHandle = parent;

#ifdef VERBOSE
    LOGD("[*] Loading key under parent identified by %08x\n", parent);
#endif

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_Load,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);


    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    *outLoaded = out;

#ifdef VERBOSE
    LOGD("[+] Key loaded with handle %08x\n", out.objectHandle);
#endif

    return EXIT_SUCCESS;
}

uint8_t
legacy_tpm2_sign(TPM_HANDLE key, uint8_t *message, uint16_t len, TPM_HANDLE *policySession, TPMT_SIGNATURE *sigOut) {
    Sign_In in;
    Sign_Out out;
#ifdef VERBOSE
    LOGD("[*] Signing\n");
#endif

    TPMI_SH_AUTH_SESSION sessionHandle0 = policySession == NULL ? TPM_RS_PW : *policySession;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes0 = policySession == NULL ? 0 : 1;
    unsigned int sessionAttributes1 = 0;
    unsigned int sessionAttributes2 = 0;

    in.keyHandle = key;
    in.digest.t.size = len;
    in.inScheme.scheme = TPM_ALG_ECDSA;
    in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    in.validation.tag = TPM_ST_HASHCHECK;
    in.validation.hierarchy = TPM_RH_NULL;
    in.validation.digest.t.size = 0;
    rc = TSS_TPM2B_Create(&in.digest.b, message, len, sizeof(TPMU_HA));
#ifdef TPM_TIME
    auto t1 = high_resolution_clock::now();
#endif

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_Sign,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    *sigOut = out.signature;
}

uint8_t tpm2_sign(TPM_HANDLE loadedKey, const TPM_HANDLE *session, TPMT_SIG_SCHEME *scheme, TPM_HASH *hash,
                  TPMT_SIGNATURE *signature) {
    Sign_In in;
    Sign_Out out;
#ifdef VERBOSE
    LOGD("[*] Signing data\n");
#endif

    TPMI_SH_AUTH_SESSION sessionHandle0 = session == NULL ? TPM_RS_PW : *session;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes0 = 0;
    unsigned int sessionAttributes1 = 0;
    unsigned int sessionAttributes2 = 0;

    if (hash == NULL) {
        LOGD("[-] TPM hash cannot be NULL\n");
        return EXIT_FAILURE;
    }
    if (signature == NULL) {
        LOGD("[-] Signature variable be NULL\n");
        return EXIT_FAILURE;
    }
    if (scheme == NULL) {
        LOGD("[-] Signature scheme cannot be NULL\n");
        return EXIT_FAILURE;
    }

    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    in.keyHandle = loadedKey;
    in.inScheme = *scheme;
    in.digest = hash->outHash;
    in.validation = hash->validation;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_Sign,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    *signature = out.signature;
    return EXIT_SUCCESS;
}

uint8_t tpm2_hash(TPM2B_MAX_BUFFER *buffer, TPM_HANDLE hierarchy, TPM_HASH *hashOut) {
    Hash_In in;
    Hash_Out out;


    if (buffer == NULL) {
        LOGD("[-] Data to be hashed must not be NULL\n");
        return EXIT_FAILURE;
    }
    if (hashOut == NULL) {
        LOGD("[-] Result buffer must not be NULL\n");
        return EXIT_FAILURE;
    }

#ifdef VERBOSE
    LOGD("[*] Hashing data\n");
#endif

    in.hashAlg = HASH_ALG;
    in.hierarchy = hierarchy;
    in.data = *buffer;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_Hash,
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    *hashOut = out;
    return EXIT_SUCCESS;
}

uint8_t tpm2_commit(TPM_HANDLE key, TPM2B_ECC_POINT *point, TPMI_SH_POLICY session, TPM2B_SENSITIVE_DATA *secret, TPM2B_ECC_PARAMETER *param,
                    COMMIT_DATA *commitData) {
    Commit_In in;
    Commit_Out out;


    if (commitData == NULL) {
        LOGD("Resulting buffer must not be NULL\n");
        return EXIT_FAILURE;
    }

#ifdef VERBOSE
    LOGD("[*] Executing Commit\n");
#endif

    in.signHandle = key;
    if (point != NULL) {
        in.P1 = *point;
    } else {
        in.P1.size = 0;
        in.P1.point.x.t.size = 0;
        in.P1.point.y.t.size = 0;
    }

    if (secret != NULL)
        in.s2 = *secret;
    else in.s2.t.size = 0;



    if (param != NULL) {
        in.y2 = *param;
    } else in.y2.t.size = 0;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_Commit,
                     session, NULL, 0,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    *commitData = out;

    return EXIT_SUCCESS;
}

uint8_t
tpm2_activateCredential(TPM_HANDLE activateHandle, TPM_HANDLE keyHandle, CHALLENGE_CREDENTIAL *cred,
                        unsigned char *certBuffer, int* certLen) {
    ActivateCredential_In in;
    ActivateCredential_Out out;

    if (certBuffer == NULL) {
        LOGD("[-] Certificate Buffer cannot be NULL\n");
        return EXIT_FAILURE;
    }
    if (cred == NULL) {
        LOGD("[-] Credential cannot be NULL\n");
        return EXIT_FAILURE;
    }
#ifdef VERBOSE
    LOGD("[+] Activating Credential for handle %08x with %08x\n", activateHandle, keyHandle);
#endif
    in.activateHandle = activateHandle;
    in.keyHandle = keyHandle;

    in.credentialBlob.t.size = cred->credential_length;
    in.secret.t.size = cred->secret_length;


    memcpy(in.credentialBlob.t.credential, cred->credential, in.credentialBlob.t.size);
    memcpy(in.secret.t.secret, cred->secret, in.secret.t.size);

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_ActivateCredential,
                     TPM_RS_PW, NULL, 0, // Authorisation for 'certified' key
                     TPM_RS_PW, NULL, 0, // Authorisation for EK
                     TPM_RH_NULL, NULL, 0);

    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    memcpy(certBuffer, out.certInfo.t.buffer, out.certInfo.t.size);
    *certLen = out.certInfo.t.size;
    return EXIT_SUCCESS;

}

uint8_t tpm2_policySigned(TPM_HANDLE publicKey, TPMI_SH_POLICY session, TPMT_SIGNATURE *signature, TPM2B_NONCE* nonce) {
    PolicySigned_In in;
    PolicySigned_Out out;

#ifdef VERBOSE
    LOGD("[*] Policy Signed\n");
#endif
    if(nonce == NULL)
        in.nonceTPM.b.size = 0;
    else in.nonceTPM = *nonce;

    in.policyRef.b.size = 0;
    in.expiration = 0;
    in.cpHashA.b.size = 0;
    in.authObject = publicKey;
    in.policySession = session;

    in.auth = *signature;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_PolicySigned,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    return rc;
}

uint8_t tpm2_getPolicyDigest(TPM_HANDLE session, uint8_t *bufferOut) {
    PolicyGetDigest_In in;
    PolicyGetDigest_Out out;
    in.policySession = session;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *) &out,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_PolicyGetDigest,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    memcpy(bufferOut, out.policyDigest.t.buffer, out.policyDigest.t.size);
    return EXIT_SUCCESS;
}


uint8_t tpm2_policyAuthorize(TPM_HANDLE session, TPMT_TK_VERIFIED* ticket, TPM2B_NAME* signingName, TPM2B_DIGEST* expected){
    PolicyAuthorize_In 		in;

#ifdef VERBOSE
    LOGD("[*] Executing Policy Authorize\n");
#endif
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;

    unsigned int		sessionAttributes0 = 0;
    unsigned int		sessionAttributes1 = 0;
    unsigned int		sessionAttributes2 = 0;

    in.checkTicket = *ticket;
    in.keySign = *signingName;
    in.approvedPolicy = *expected;
    in.policyRef.t.size = 0;
    in.policySession = session;

    rc = TSS_Execute(ctx,
                           NULL,
                           (COMMAND_PARAMETERS*)&in,
                           NULL,
                           TPM_CC_PolicyAuthorize,
                           sessionHandle0, NULL, sessionAttributes0,
                           sessionHandle1, NULL, sessionAttributes1,
                           sessionHandle2, NULL, sessionAttributes2,
                           TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;}

uint8_t tpm2_policyCommandCode(TPM_HANDLE session, TPM_CC commandCode){
    PolicyCommandCode_In 	in;

#ifdef VERBOSE
    LOGD("[*] Executing PolicyCommandCode with Code %04x\n",commandCode);
#endif

    in.policySession = session;
    in.code = commandCode;

    rc = TSS_Execute(ctx,
                     NULL,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_PolicyCommandCode,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}


uint8_t tpm2_policyPCR(TPM_HANDLE session, TPML_PCR_SELECTION *pcrSelection) {
    PolicyPCR_In in;
    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RH_NULL;
    unsigned int sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle1 = TPM_RH_NULL;
    unsigned int sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION sessionHandle2 = TPM_RH_NULL;
    unsigned int sessionAttributes2 = 0;
#ifdef VERBOSE
    LOGD("[*] Policy PCR\n");
#endif
    in.pcrs = *pcrSelection;
    in.pcrDigest.t.size = 0;
    in.policySession = session;

    rc = TSS_Execute(ctx,
                     NULL,
                     (COMMAND_PARAMETERS *) &in,
                     NULL,
                     TPM_CC_PolicyPCR,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;

}

uint8_t tpm2_certifyCreation(TPM_HANDLE key, TPM_KEY* keyInfo, TPM_HANDLE signingHandle, TPMT_SIG_SCHEME* signScheme, CREATION_CERT *cert) {

    CertifyCreation_In 		in;
    CertifyCreation_Out 	out;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
#ifdef VERBOSE
    LOGD("[*] Certify Creation\n");
#endif
    in.objectHandle = key;
    in.signHandle = signingHandle;
    in.creationHash = keyInfo->creationHash;
    in.creationTicket = keyInfo->creationTicket;
    in.qualifyingData.t.size = 0;
    in.inScheme = *signScheme;



    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *)&out,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_CertifyCreation,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;

}

uint8_t tpm2_evictControl(TPM_HANDLE handle, TPM_HANDLE persistentHandle) {
    EvictControl_In in;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
    in.auth = TPM_RH_OWNER;
    in.objectHandle = handle;
    in.persistentHandle = persistentHandle;

#ifdef VERBOSE
    LOGD("[*] Evict Control\n");
#endif

    rc = TSS_Execute(ctx,
                     NULL,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_EvictControl,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return rc;
    }
    return EXIT_SUCCESS;

}

uint8_t tpm2_certify(TPM_HANDLE keyToCertify, TPM_HANDLE signingHandle, TPMT_SIG_SCHEME *sigScheme, KEY_CERT *certOut) {
    Certify_In 		in;
    Certify_Out 	out;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RS_PW;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    in.objectHandle = keyToCertify;
    in.inScheme = *sigScheme;
    in.signHandle = signingHandle;
    in.qualifyingData.t.size = 0;
    const char			*keyPassword = NULL;
    const char			*objectPassword = NULL;
#ifdef VERBOSE
    LOGD("[*] Certify\n");
#endif

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *)&out,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_Certify,
                     sessionHandle0, objectPassword, sessionAttributes0,
                     sessionHandle1, keyPassword, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    *certOut = out;

    return EXIT_SUCCESS;

}


LoadExternal_Out tpm2_loadExternal(TPM2B_PUBLIC *publicKey, TPMI_RH_HIERARCHY hierarchy, TPM_HANDLE* loadOut) {

#ifdef VERBOSE
    LOGD("[*] Loading External Key\n");
#endif
    LoadExternal_In 		in;
    LoadExternal_Out 		out;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;


    in.inPrivate.t.size = 0;
    in.hierarchy = hierarchy;
    in.inPublic = *publicKey;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *)&out,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_LoadExternal,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);

    *loadOut = out.objectHandle;

    return out;

}

uint8_t tpm2_createLoaded(TPM2B_PUBLIC *keytemplate, TPM_HANDLE parent, TPM_HANDLE *handleOut) {
#ifdef VERBOSE
    LOGD("[*] Creating and Loading Key\n");
#endif
    CreateLoaded_In 		in;
    CreateLoaded_Out 		out;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    uint16_t written = 0;
    uint32_t size = sizeof(in.inPublic.t.buffer);
    uint8_t *buffer = in.inPublic.t.buffer;
    TSS_TPMT_PUBLIC_Marshalu(&keytemplate->publicArea, &written, &buffer, &size);

    in.parentHandle = parent;
    in.inSensitive.sensitive.data.t.size = 0;
    in.inSensitive.sensitive.userAuth.t.size = 0;
    in.inPublic.t.size = written;


    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *)&out,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_CreateLoaded,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);
#ifdef VERBOSE
    if (rc != TPM_RC_SUCCESS) {
        handle_TPM_error(rc, NOT_CRITICAL);
        return EXIT_FAILURE;
    }
    if(rc == 0){
        LOGD("[+] Key created and loaded under handle %08x\n",out.objectHandle);
    } else LOGD("[-] Key creation and load failed\n");
#endif

    *handleOut = out.objectHandle;
}

uint8_t tpm2_GetRandom(uint8_t noBytes, uint8_t* buff) {
    TPM_RC                      rc = 0;
    GetRandom_In                in;
    GetRandom_Out               out;
    TPMI_SH_AUTH_SESSION        sessionHandle0 = TPM_RH_NULL;
    unsigned int                sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION        sessionHandle1 = TPM_RH_NULL;
    unsigned int                sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION        sessionHandle2 = TPM_RH_NULL;
    unsigned int                sessionAttributes2 = 0;

    in.bytesRequested = noBytes;

    rc = TSS_Execute(ctx,
                     (RESPONSE_PARAMETERS *)&out,
                     (COMMAND_PARAMETERS *)&in,
                     NULL,
                     TPM_CC_GetRandom,
                     sessionHandle0, NULL, sessionAttributes0,
                     sessionHandle1, NULL, sessionAttributes1,
                     sessionHandle2, NULL, sessionAttributes2,
                     TPM_RH_NULL, NULL, 0);

    memcpy(buff,out.randomBytes.t.buffer,noBytes);

    return rc;
}

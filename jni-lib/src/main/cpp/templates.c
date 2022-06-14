//
// Created by benlar on 12/20/21.
//
#include "templates.h"

#include "objecttemplates.h"

void buildDAAKeyTemplate(TPM2B_PUBLIC *public, TPM2B_DIGEST *policyDigest) {


    TPMT_PUBLIC *publicArea = &public->publicArea;

    publicArea->type = TPM_ALG_ECC;
    publicArea->nameAlg = TPM_ALG_SHA256;

    publicArea->objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
                                       TPMA_OBJECT_NODA |
                                       TPMA_OBJECT_FIXEDPARENT |
                                       TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                       TPMA_OBJECT_RESTRICTED |
                                       TPMA_OBJECT_SIGN;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_USERWITHAUTH;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;

    publicArea->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_ECDAA;
    publicArea->parameters.eccDetail.scheme.details.ecdaa.hashAlg = TPM_ALG_SHA256;
    publicArea->parameters.eccDetail.scheme.details.ecdaa.count = 1;
    publicArea->parameters.eccDetail.curveID = TPM_ECC_BN_P256;
    publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    publicArea->unique.ecc.x.t.size = 0;
    publicArea->unique.ecc.y.t.size = 0;

    if (policyDigest == NULL)
        publicArea->authPolicy.t.size = 0;
    else {
        publicArea->authPolicy = *policyDigest;
    }

}

void buildRSAKey(TPM2B_PUBLIC *public, TPM2B_DIGEST *policyDigest) {


    TPMA_OBJECT add;
    TPMA_OBJECT rem;
    add.val = 0;
    rem.val = 0;

    add.val |= TPMA_OBJECT_NODA;
    asymPublicTemplate(&public->publicArea,add,rem,TYPE_ST,TPM_ALG_RSA,2048,0,TPM_ALG_SHA256,TPM_ALG_SHA256,NULL);

    /*
    TPMT_PUBLIC *publicArea = &public->publicArea;

    publicArea->type = TPM_ALG_RSA;
    publicArea->nameAlg = TPM_ALG_SHA256;


    publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
    publicArea->objectAttributes.val |= TPMA_OBJECT_RESTRICTED;

    publicArea->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    publicArea->parameters.rsaDetail.scheme.scheme = TPM_ALG_RSASSA;
    publicArea->parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM_ALG_SHA256;
    publicArea->parameters.rsaDetail.keyBits = 2048;
    publicArea->parameters.rsaDetail.exponent = 0;
    publicArea->unique.rsa.t.size = 0;



    if (policyDigest == NULL)
        publicArea->authPolicy.t.size = 0;
    else {
        publicArea->authPolicy = *policyDigest;
    }


}

void buildUnrestrictedSigningKey(TPM2B_PUBLIC *pubIn, TPM2B_DIGEST *policyDigest) {

    TPMT_PUBLIC* publicArea = &pubIn->publicArea;

    TPMA_OBJECT addObjectAttributes;
    TPMA_OBJECT deleteObjectAttributes;

    addObjectAttributes.val = 0;
    addObjectAttributes.val |= TPMA_OBJECT_NODA;
    deleteObjectAttributes.val = 0;
    if (policyDigest != NULL) {
        publicArea->authPolicy = *policyDigest;
    } else {
        publicArea->authPolicy.t.size = 0;
    }
    publicArea->objectAttributes = addObjectAttributes;
    publicArea->type = TPM_ALG_ECC;
    publicArea->nameAlg = TPM_ALG_SHA256;
    publicArea->objectAttributes.val |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    publicArea->objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH; // Set (ADMIN role authorization must be provided by a policy session.)
    publicArea->objectAttributes.val |= TPMA_OBJECT_SIGN;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_DECRYPT;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_ADMINWITHPOLICY;
    publicArea->objectAttributes.val |= TPMA_OBJECT_ADMINWITHPOLICY;
    publicArea->objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
    publicArea->objectAttributes.val &= ~deleteObjectAttributes.val;
    publicArea->parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
    publicArea->parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
    publicArea->parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    publicArea->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    publicArea->parameters.eccDetail.kdf.details.mgf1.hashAlg = TPM_ALG_SHA256;
    publicArea->unique.ecc.x.t.size = 0;
    publicArea->unique.ecc.y.t.size = 0;*/
}

//
// Created by benlar on 1/4/22.
//
#include <ibmtss/TPM_Types.h>
#include "policy.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "ibmtss/tssmarshal.h"

void cc_to_byteArray(uint16_t cc, uint8_t *out) {
    out[0] = (cc >> 24) & 0xFF;
    out[1] = (cc >> 16) & 0xFF;
    out[2] = (cc >> 8) & 0xFF;
    out[3] = (cc >> 0) & 0xFF;
}

void updatePolicySigned(uint8_t *authorizing_key_name, size_t name_len, uint8_t *policyDigest) {

    uint8_t cc[CC_LEN];
    cc_to_byteArray(TPM_CC_PolicySigned, cc);

    hash_begin(HASH_ALG);

    // Create policy
    hash_update(policyDigest, DIGEST_SIZE);
    hash_update(cc, CC_LEN);
    hash_update(authorizing_key_name, name_len);
    hash_final(policyDigest);

    // We need to double hash
    hash_begin(HASH_ALG);
    hash_update(policyDigest, DIGEST_SIZE);
    hash_final(policyDigest);

    // We don't include PolicyRef for now.
}


//  policyDigestnew ≔ HpolicyAlg(policyDigestold || TPM_CC_PolicyPCR || pcrs || digestTPM) (19)
void updatePolicyPCR(TPML_PCR_SELECTION *pcr_selection, uint8_t *expected_state_digest,
                     uint8_t *policyDigest) {
    uint8_t cc[CC_LEN];
    cc_to_byteArray(TPM_CC_PolicyPCR, cc);
    uint8_t pcrs[sizeof(TPML_PCR_SELECTION)];
    uint8_t *buffer;
    buffer = pcrs;
    uint16_t pcrSize = 0;

    // Get pcr size and PCRs marshalled
    if(TSS_TPML_PCR_SELECTION_Marshal(pcr_selection,&pcrSize,&buffer,NULL) != 0){
        printf("[-] Error in unmarshal PCR Selction\n");
        exit(-1);
    } else if(pcrSize == 0 || pcrSize > 100){
        printf("[-] Error in unmarshal PCR Selction\n");
        exit(-1);
    }

    hash_begin(HASH_ALG);
    hash_update(policyDigest, DIGEST_SIZE);
    hash_update(cc, CC_LEN);
    hash_update(pcrs,pcrSize);
    hash_update(expected_state_digest, DIGEST_SIZE);
    hash_final(policyDigest);

}

TPML_PCR_SELECTION get_pcr_selection(int num, ...) {
    TPML_PCR_SELECTION selection;
    selection.count = 1; // We only have one bank (could be multiple ofc)
    selection.pcrSelections[0].hash = HASH_ALG;
    selection.pcrSelections[0].sizeofSelect = 3;    /* hard code 24 PCRs */

    for(int i = 0; i < PCR_SELECT_MAX; i++)
        selection.pcrSelections[0].pcrSelect[i] = 0x00;

    va_list valist;
    va_start(valist, num);

    for (int i = 0; i < num; i++) {
        int bit = va_arg(valist, int);
        int bitToSet = ((bit - 1) % 8);
        int byteToSet = (int) ((bit - 1) / 8);
        selection.pcrSelections[0].pcrSelect[byteToSet] |= 1 << bitToSet;
    }

    return selection;


}

void updatePolicyAuthorize(uint8_t *authorizing_key_name, size_t name_len, uint8_t *policyDigest) {
    uint8_t cc[CC_LEN];
    cc_to_byteArray(TPM_CC_PolicyAuthorize, cc);

    hash_begin(HASH_ALG);
    hash_update(policyDigest, DIGEST_SIZE);
    hash_update(cc, CC_LEN);
    hash_update(authorizing_key_name,name_len);
    hash_final(policyDigest);

    // Dobbel
    hash_begin(HASH_ALG);
    hash_update(policyDigest, DIGEST_SIZE);
    hash_final(policyDigest);

}

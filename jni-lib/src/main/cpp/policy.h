//
// Created by benlar on 1/4/22.
//

#ifndef DAA_BRIDGE_V2_POLICY_H
#define DAA_BRIDGE_V2_POLICY_H

#include <ibmtss/Implementation.h>
#include "stddef.h"
#include "stdint.h"
#include "hash.h"
#include "defines.h"


TPML_PCR_SELECTION get_pcr_selection(int num, ...);

void updatePolicySigned(uint8_t* authorizing_key_name, size_t name_len, uint8_t* policyDigest);

void updatePolicyAuthorize(uint8_t* authorizing_key_name, size_t name_len, uint8_t* policyDigest);

//  policyDigestnew ≔ HpolicyAlg(policyDigestold || TPM_CC_PolicyPCR || pcrs || digestTPM) (19)
void updatePolicyPCR(TPML_PCR_SELECTION* pcr_selection, uint8_t* expected_state_digest, uint8_t* policyDigest);



#endif //DAA_BRIDGE_V2_POLICY_H

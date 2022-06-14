//
// Created by benlar on 12/20/21.
//

#ifndef DAA_BRIDGE_TEMPLATES_H
#define DAA_BRIDGE_TEMPLATES_H

#include "ibmtss/TPM_Types.h"


void buildDAAKeyTemplate(TPM2B_PUBLIC *publicArea, TPM2B_DIGEST *policyDigest);
void buildRSAKey(TPM2B_PUBLIC *publicArea, TPM2B_DIGEST *policyDigest);

#endif //DAA_BRIDGE_TEMPLATES_H

//
// Created by benlar on 1/7/22.
//

#include "daa_pairings.h"
#include "issPk.h"
#include <ecp2_FP256BN.h>
#include <ecp_FP256BN.h>
#include <fp12_FP256BN.h>
#include <pair_FP256BN.h>
#include "memory.h"


void bin2ecp(uint8_t *binx, uint8_t *biny, int component_len, ECP_FP256BN *res) {
    octet c_o;
    c_o.len = 2 * component_len + 1;
    c_o.val = malloc(c_o.len);
    c_o.val[0] = 0x04;
    memcpy(&c_o.val[1], binx, component_len);
    memcpy(&c_o.val[component_len + 1], biny, component_len);

    ECP_FP256BN_fromOctet(res, &c_o);
    free(c_o.val);


}


/*
 * Function:  verify_credential
 * --------------------
 *  Verifies that the credential is Issued by the correct Issuer
 *
 *  ctx:                    The DAA Context
 *  credential:             The credential from the signer
 *
 *  returns: 0 on success, otherwise error code
 */
uint8_t verify_credential(DAA_CONTEXT *ctx, DAA_CREDENTIAL *credential) {
    ECP2_FP256BN rom;
    ECP2_FP256BN_generator(&rom);


    ECP2_FP256BN x_ecp2, y_ecp2;

    // Make Octet
    octet x_c_oc;
    x_c_oc.len = ISSUER_PK_LEN / 2;
    x_c_oc.val = issPk; // Implicit conversion - should we copy?

    octet y_c_oc;
    y_c_oc.len = ISSUER_PK_LEN / 2;
    y_c_oc.val = &issPk[ISSUER_PK_LEN / 2]; // Implicit conversion - should we copy?


    ECP2_FP256BN_fromOctet(&x_ecp2, &x_c_oc);
    ECP2_FP256BN_fromOctet(&y_ecp2, &y_c_oc);

    ECP_FP256BN c1, c2, c3, c4;
    bin2ecp(credential->points[0].x_coord, credential->points[0].y_coord, ctx->ecc_point_len, &c1);
    bin2ecp(credential->points[1].x_coord, credential->points[1].y_coord, ctx->ecc_point_len, &c2);
    bin2ecp(credential->points[2].x_coord, credential->points[2].y_coord, ctx->ecc_point_len, &c3);
    bin2ecp(credential->points[3].x_coord, credential->points[3].y_coord, ctx->ecc_point_len, &c4);

    FP12_FP256BN lhs, rhs;

    PAIR_FP256BN_ate(&lhs, &y_ecp2, &c1);
    PAIR_FP256BN_fexp(&lhs);

    PAIR_FP256BN_ate(&rhs, &rom, &c2);
    PAIR_FP256BN_fexp(&rhs);

    if (FP12_FP256BN_equals(&lhs, &rhs) == 0) {
        return RC_BAD_CREDENTIAL_P1;
    }

    ECP_FP256BN_add(&c4, &c1);

    PAIR_FP256BN_ate(&lhs, &x_ecp2, &c4);
    PAIR_FP256BN_fexp(&lhs);

    PAIR_FP256BN_ate(&rhs, &rom, &c3);
    PAIR_FP256BN_fexp(&rhs);

    if (FP12_FP256BN_equals(&lhs, &rhs) == 0) {
        return RC_BAD_CREDENTIAL_P2;
    }


    return 0;

}
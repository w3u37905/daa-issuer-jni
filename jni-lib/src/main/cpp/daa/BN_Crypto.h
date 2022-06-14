//
// Created by benlar on 12/24/21.
//

#ifndef DAA_BRIDGE_BN_CRYPTO_H
#define DAA_BRIDGE_BN_CRYPTO_H

#include <openssl/ec.h>


//TODO: I think we can use the samme ECGroup

EC_GROUP *get_ec_group_bnp256(void);
BIGNUM *BN_Mod(unsigned char *num, unsigned char *mod);
uint8_t EC_Point_Multiplication(BIGNUM *multiplier, unsigned char *pX, unsigned char *pY,  EC_POINT *resultingPoint);
uint8_t EC_Generator_Multiplication(unsigned char *multiplier, int size, EC_POINT *resPtr);
uint8_t EC_Point_inverse(EC_POINT *p);
uint8_t EC_Add_Points(EC_POINT* p1, EC_POINT* p2, EC_POINT* resPtr);
uint8_t getBinaryCoordinates(EC_POINT* p, unsigned char* x, unsigned char* y);

#endif //DAA_BRIDGE_BN_CRYPTO_H

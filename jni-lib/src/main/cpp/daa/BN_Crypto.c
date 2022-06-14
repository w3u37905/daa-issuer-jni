//
// Created by benlar on 12/24/21.
//

#include "BN_Crypto.h"

unsigned char bnp256_p[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD, 0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4,
                              0x9F, 0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x98, 0x0A, 0x82, 0xD3, 0x29, 0x2D, 0xDB, 0xAE, 0xD3,
                              0x30, 0x13};

unsigned char BNP256_ORDER[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD, 0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71,
                                  0xA4, 0x9E, 0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A, 0xF6, 0x2D, 0x53, 0x6C,
                                  0xD1, 0x0B, 0x50, 0x0D};

unsigned char bnp256_gX[1] = {0x01};
unsigned char bnp256_gY[1] = {0x02};

BIGNUM *BN_Mod(unsigned char *num, unsigned char *mod) {


    BN_CTX *ctx = BN_CTX_new(); // @1

    BIGNUM *modPtr = BN_new(); // @2
    BIGNUM *numPtr = BN_new(); // @3
    BIGNUM *resPtr = BN_new(); // @4

    /* We begin by converting our values to Big Numbers */
    // converts the positive integer in big-endian form of length len at s into a BIGNUM
    // and places it in ret. If ret is NULL, a new BIGNUM is created.
    BN_bin2bn(mod, 32, modPtr);
    BN_bin2bn(num, 32, numPtr);

    // Execute the operation
    // Tested OK / BL
    if (1 != BN_nnmod(resPtr, numPtr, modPtr, ctx)) {
        printf("[-] Error in calculating mod\n");
        BN_free(modPtr);    // @1
        BN_free(numPtr);    // @2
        BN_CTX_free(ctx);   // @1

        return NULL;

    }

    // Cleanup
    BN_free(modPtr);    // @1
    BN_free(numPtr);    // @2
    BN_CTX_free(ctx);   // @1


    return resPtr;
}


// CHris Newtons code, with minor changes
EC_GROUP *get_ec_group_bnp256(void) {
    int ok = 0;
    EC_GROUP *curve = NULL;
    EC_POINT *generator = NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *tmp_1 = NULL, *tmp_2 = NULL, *tmp_3 = NULL;

    // Added those
    unsigned char bnp256_a[1] = {0x00};
    unsigned char bnp256_b[1] = {0x03};
    unsigned char bnp256_gX_[1] = {0x01};
    unsigned char bnp256_gy_[1] = {0x02};


    if ((tmp_1 = BN_bin2bn(bnp256_p, 32, NULL)) == NULL)
        goto err;
    if ((tmp_2 = BN_bin2bn(bnp256_a, 1, NULL)) == NULL)
        goto err;
    if ((tmp_3 = BN_bin2bn(bnp256_b, 1, NULL)) == NULL)
        goto err;
    if ((curve = EC_GROUP_new_curve_GFp(tmp_1, tmp_2, tmp_3, NULL)) == NULL)
        goto err;


    /* build generator */
    generator = EC_POINT_new(curve);
    if (generator == NULL)
        goto err;
    if ((tmp_1 = BN_bin2bn(bnp256_gX_, 1, tmp_1)) == NULL)
        goto err;
    if ((tmp_2 = BN_bin2bn(bnp256_gy_, 1, tmp_2)) == NULL)
        goto err;
    if (1 != EC_POINT_set_affine_coordinates_GFp(curve, generator, tmp_1, tmp_2, ctx))
        goto err;

//	std::cout << "gX: " << BN_bn2hex(tmp_1) << '\n';
//	std::cout << "gY: " << BN_bn2hex(tmp_2) << '\n';

    if ((tmp_1 = BN_bin2bn(BNP256_ORDER, 32, tmp_1)) == NULL)
        goto err;
    BN_one(tmp_2);
    if (1 != EC_GROUP_set_generator(curve, generator, tmp_1, tmp_2))
        goto err;

//	std::cout << "order: " << BN_bn2hex(tmp_1) << '\n';

    ok = 1;
//	std::cout << "Curve generation succeeded\n";
    err:
    if (tmp_1)
        BN_free(tmp_1);
    if (tmp_2)
        BN_free(tmp_2);
    if (tmp_3)
        BN_free(tmp_3);
    if (generator)
        EC_POINT_free(generator);
    if (ctx)
        BN_CTX_free(ctx);
    if (!ok) {
        printf("[-] Error in creating curve\n");
        EC_GROUP_free(curve);
        curve = NULL;
    }
//	std::cout << "Returning to caller after generating curve\n";
    return (curve);
}

uint8_t EC_Add_Points(EC_POINT *p1, EC_POINT *p2, EC_POINT *resPtr) {
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *ecgrp = get_ec_group_bnp256();    // @2


    if (1 != EC_POINT_add(ecgrp, resPtr, p1, p2, ctx)) {
        printf("[-] Error in adding points\n");
        BN_CTX_free(ctx); // @ 1
        EC_GROUP_free(ecgrp);

        return EXIT_FAILURE;
    }

    BN_CTX_free(ctx); // @ 1
    EC_GROUP_free(ecgrp);

    return EXIT_SUCCESS;
}

uint8_t EC_Point_inverse(EC_POINT *p) {
    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *ecgrp = get_ec_group_bnp256();    // @2

    if (1 != EC_POINT_invert(ecgrp, p, ctx)) {
        printf("[-] Not able to invert point\n");
        BN_CTX_free(ctx); // @ 1
        EC_GROUP_free(ecgrp);

        return EXIT_FAILURE;
    }
    BN_CTX_free(ctx); // @ 1
    EC_GROUP_free(ecgrp);

    return EXIT_SUCCESS;


}

uint8_t
EC_Generator_Multiplication(unsigned char *multiplier, int size, EC_POINT *resPtr) {


    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *ecgrp = get_ec_group_bnp256();    // @2

    BIGNUM *bn_multiplier = BN_new(); // @2

    // Concert input to bignumber
    BN_bin2bn(multiplier, size, bn_multiplier);

    if (1 != EC_POINT_mul(ecgrp, resPtr, bn_multiplier, NULL, NULL, ctx)) {
        printf("[-] Error in Generator Multiplication\n");
        BN_free(bn_multiplier); // @ 2
        BN_CTX_free(ctx); // @ 1
        EC_GROUP_free(ecgrp);

        return EXIT_FAILURE;
    }
    BN_free(bn_multiplier); // @ 2
    BN_CTX_free(ctx); // @ 1
    EC_GROUP_free(ecgrp);

    return EXIT_SUCCESS;
}


uint8_t EC_Point_Multiplication(BIGNUM *multiplier, unsigned char *pX, unsigned char *pY,
                                EC_POINT *resultingPoint) {

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *ecgrp = get_ec_group_bnp256();    // @2

    // We define our points
    EC_POINT *startingPoint = EC_POINT_new(ecgrp); //@2

    // We now take our starting point and insert our coordinates in them
    BIGNUM *x = BN_new(); // @4
    BIGNUM *y = BN_new(); // @5



    // Convert our data to BIGNUM
    BN_bin2bn(pX, 32, x);
    BN_bin2bn(pY, 32, y);


    // Insert
    if (1 != EC_POINT_set_affine_coordinates_GFp(ecgrp, startingPoint, x, y, ctx)) {
        printf("[-] There was an error creating points out of the credentials (Point's are probably not on curve) \n");
        BN_free(y); // @ 5
        BN_free(x); // @ 4

        EC_POINT_free(startingPoint); // @2
        BN_CTX_free(ctx);   // @1
        EC_GROUP_free(ecgrp);

        return EXIT_FAILURE;
    }

    // Now we can do the multiplication
    if (1 != EC_POINT_mul(ecgrp, resultingPoint, NULL, startingPoint, multiplier, ctx)) {
        printf("[-] There was an error during multiplication\n");
        BN_free(y); // @ 5
        BN_free(x); // @ 4

        EC_POINT_free(startingPoint); // @2
        BN_CTX_free(ctx);   // @1
        EC_GROUP_free(ecgrp);

        return EXIT_FAILURE;
    }

    // Now we're done, and we will simply serialize the point to a binary buffer again
    // TODO, can't we store the points as openSSL points?

    BN_free(y); // @ 5
    BN_free(x); // @ 4
    EC_POINT_free(startingPoint); // @2

    // TODO: Can we reust?
    BIGNUM *x_new = BN_new(); // @6
    BIGNUM *y_new = BN_new(); // @7

    if (1 != EC_POINT_get_affine_coordinates_GFp(ecgrp, resultingPoint, x_new, y_new, ctx)) {
        printf("[-] Error in converting new point to X/Y\n");
        BN_free(y_new); // @ 7
        BN_free(x_new); // @ 6
        BN_CTX_free(ctx);   // @1
        EC_GROUP_free(ecgrp);

        return EXIT_FAILURE;
    }

    // Update inputs
    BN_bn2bin(x_new, pX);
    BN_bn2bin(y_new, pY);

    BN_free(y_new); // @ 7
    BN_free(x_new); // @ 6
    EC_GROUP_free(ecgrp);
    BN_CTX_free(ctx);   // @1

    return EXIT_SUCCESS;


}

// Size 32
uint8_t getBinaryCoordinates(EC_POINT *p, unsigned char *x, unsigned char *y) {
    BIGNUM *pX = BN_new(); // @1
    BIGNUM *pY = BN_new(); // @2

    BN_CTX *ctx = BN_CTX_new();
    EC_GROUP *ecgrp = get_ec_group_bnp256();    // @2

    if (1 != EC_POINT_get_affine_coordinates_GFp(ecgrp, p, pX, pY, ctx)) {
        printf("[-] Not able to get coordinates\n");
        BN_free(pX);
        BN_free(pY);
        BN_CTX_free(ctx);
        EC_GROUP_free(ecgrp);
        return EXIT_FAILURE;
    }

    BN_bn2bin(pX, x);
    BN_bn2bin(pY, y);
    EC_GROUP_free(ecgrp);

    BN_free(pX);
    BN_free(pY);
    BN_CTX_free(ctx);
    return EXIT_SUCCESS;
}

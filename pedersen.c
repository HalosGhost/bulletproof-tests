#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_generator.h"

typedef unsigned char Hash[32];

static unsigned long
randomnumber() {
    
    FILE * f = fopen("/dev/urandom", "r");
    if ( !f ) {
        return 0;
    }

    unsigned long l = 0;
    fread(&l, 1, sizeof l, f);
    fclose(f);

    return l;
}

static void
randomhash(Hash hash) {

    for ( size_t i = 0, n = sizeof(Hash) / sizeof(unsigned long); i < n; ++i ) {
        unsigned long v = randomnumber();
        memcpy(hash + (i * sizeof(unsigned long)), &v, sizeof(v));
    }
}

signed
main (void) {

    unsigned long values[4] = {0};
    for ( size_t i = 0; i < 2; ++i ) {
        values[i] = randomnumber() % UINT_MAX;
    }
    values[2] = (values[0] + values[1]) / 2;
    values[3] = (values[0] + values[1]) - values[2];

    Hash blinds[4] = {{0}};
    for ( size_t i = 0; i < 3; ++i ) {
        randomhash(blinds[i]);
    }

    const unsigned char * b_ptrs [] = { blinds[0], blinds[1], blinds[2] };

    secp256k1_context * s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context * v_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    if ( !secp256k1_pedersen_blind_sum(s_ctx, blinds[3], b_ptrs, 3, 2) ) {
        goto cleanup;
    }

    secp256k1_pedersen_commitment commits[4] = {0};
    for ( size_t i = 0; i < 4; ++i ) {
        unsigned long v = values[i];
        const unsigned char * r = blinds[i];
        if ( !secp256k1_pedersen_commit(s_ctx, &commits[i], r, v, secp256k1_generator_h) ) {
            goto cleanup;
        }
    }

    const secp256k1_pedersen_commitment * p_ptrs [] = { &commits[0], &commits[1] };
    const secp256k1_pedersen_commitment * n_ptrs [] = { &commits[2], &commits[3] };

    if ( !secp256k1_pedersen_verify_tally(v_ctx, p_ptrs, 2, n_ptrs, 2) ) {
        goto cleanup;
    }

    printf("commits balanced!\n");

    cleanup:
        secp256k1_context_destroy(s_ctx);
        secp256k1_context_destroy(v_ctx);
}


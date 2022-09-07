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

    FILE * f = fopen("/dev/urandom", "r");
    if ( !f ) {
        return;
    }

    fread(hash, 1, sizeof(Hash), f);
    fclose(f);
}

// uncomment next line to test spending minted inputs
//#define minted_inputs
#define in_count 2
#define out_count 2

signed
main (void) {

    // roll input values and blinding factors
    unsigned long in_sum = 0;
    unsigned long in_vals[in_count] = {0};
    for ( size_t i = 0; i < in_count; ++i ) {
        in_vals[i] = randomnumber() % UINT_MAX;
        in_sum += in_vals[i];
    }

    Hash in_blinds[in_count] = {{0}};
    for ( size_t i = 0; i < in_count; ++i ) {
        #ifndef minted_inputs
        randomhash(in_blinds[i]);
        #endif
    }

    // calculate balanced output values
    unsigned long out_sum = 0;
    unsigned long out_vals[out_count] = {0};
    for ( size_t i = 0; i < out_count - 1; ++i ) {
        out_vals[i] = in_sum / out_count;
        out_sum += out_vals[i];
    };

    out_vals[out_count - 1] = in_sum - out_sum;
    out_sum += out_vals[out_count - 1];

    // roll all but last output blinding factor
    Hash out_blinds[out_count] = {{0}};
    for ( size_t i = 0; i < out_count - 1; ++i ) {
        randomhash(out_blinds[i]);
    }

    // collect all rolled blinding factors
    const unsigned char * b_ptrs [in_count + out_count - 1] = {0};
    for ( size_t i = 0; i < in_count; ++i ) {
        b_ptrs[i] = in_blinds[i];
    }
    for ( size_t i = 0; i < out_count - 1; ++i ) {
        b_ptrs[i + in_count] = out_blinds[i];
    }

    secp256k1_context * s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context * v_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

    // calculate last blinding factor
    if ( !secp256k1_pedersen_blind_sum(s_ctx, out_blinds[out_count - 1], b_ptrs, in_count + out_count - 1, in_count) ) {
        goto cleanup;
    }

    #if defined(minted_inputs) && out_count == 2
    {
        Hash negated = {0};
        memcpy(negated, out_blinds[0], sizeof(Hash));
        secp256k1_ec_seckey_negate(s_ctx, negated);
        if ( memcmp(out_blinds[1], negated, sizeof(Hash)) ) {
            goto cleanup;
        }
    }
    #endif

    // make commitments
    secp256k1_pedersen_commitment in_commits[in_count] = {0};
    for ( size_t i = 0; i < in_count; ++i ) {
        unsigned long v = in_vals[i];
        const unsigned char * r = in_blinds[i];
        if ( !secp256k1_pedersen_commit(s_ctx, &in_commits[i], r, v, secp256k1_generator_h) ) {
            goto cleanup;
        }
    }

    secp256k1_pedersen_commitment out_commits[out_count] = {0};
    for ( size_t i = 0; i < out_count; ++i ) {
        unsigned long v = out_vals[i];
        const unsigned char * r = out_blinds[i];
        if ( !secp256k1_pedersen_commit(s_ctx, &out_commits[i], r, v, secp256k1_generator_h) ) {
            goto cleanup;
        }
    }

    const secp256k1_pedersen_commitment * in_ptrs [in_count] = {0};
    for ( size_t i = 0; i < in_count; ++i ) {
        in_ptrs[i] = &in_commits[i];
    }

    const secp256k1_pedersen_commitment * out_ptrs [out_count] = {0};
    for ( size_t i = 0; i < out_count; ++i ) {
        out_ptrs[i] = &out_commits[i];
    }

    // verify balance
    if ( !secp256k1_pedersen_verify_tally(v_ctx, in_ptrs, in_count, out_ptrs, out_count) ) {
        goto cleanup;
    }

    printf("commits balanced!\n");

    cleanup:
        secp256k1_context_destroy(s_ctx);
        secp256k1_context_destroy(v_ctx);
}


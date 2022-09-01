#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "secp256k1.h"
#include "secp256k1_bulletproofs.h"

unsigned long
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

signed
prove (secp256k1_context * ctx, unsigned long value, secp256k1_pedersen_commitment * commitment, unsigned char * proof, size_t * prooflen) {

    signed status = EXIT_SUCCESS;

    // 128 == 2*n_bits (allows for proving up to 64 bits)
    secp256k1_bulletproofs_generators * gens = secp256k1_bulletproofs_generators_create(ctx, 128);
    if ( !gens ) {
        fputs("Failed to allocate bulletproofs generators\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    unsigned char blind [32] = { 0 };
    unsigned char r = randomnumber();
    memset(blind, r, 32);

    unsigned char nonce [32] = { 0 };
    r = randomnumber();
    memset(nonce, r, 32);

    signed res = secp256k1_pedersen_commit(ctx, commitment, blind, value, secp256k1_generator_h);
    if ( res != 1 ) {
        fputs("Failed to create commitment\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    res = secp256k1_bulletproofs_rangeproof_uncompressed_prove(
        ctx,
        gens,
        secp256k1_generator_h,
        proof,
        prooflen,
        32, // n_bits
        value,
        0, // min
        commitment,
        blind,
        nonce,
        NULL, // enc_data
        NULL, // extra_commit
        0     // extra_commit length
    );

    if ( res == 0 ) {
        fputs("Failed to create proof\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    cleanup:
        if ( gens ) { secp256k1_bulletproofs_generators_destroy(ctx, gens); }
        return status;
}

signed
verify (secp256k1_context * ctx, secp256k1_pedersen_commitment * commitment, unsigned char * proof, size_t prooflen) {

    signed status = EXIT_SUCCESS;
    
    secp256k1_scratch_space * scratch = secp256k1_scratch_space_create(ctx, 100 * 1024);

    // 128 == 2*n_bits (allows for proving up to 64 bits)
    secp256k1_bulletproofs_generators * gens = secp256k1_bulletproofs_generators_create(ctx, 128);
    if ( !gens ) {
        fputs("Failed to allocate bulletproofs generators\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    signed res = secp256k1_bulletproofs_rangeproof_uncompressed_verify(
        ctx,
        scratch,
        gens,
        secp256k1_generator_h,
        proof,
        prooflen,
        0, // min still required (why?)
        commitment,
        NULL, // extra_commit
        0     // extra_commit length
    );

    if ( res == 0 ) {
        fputs("Failed to verify proof\n", stderr);
        status = EXIT_FAILURE;
        goto cleanup;
    }

    cleanup:
        secp256k1_scratch_space_destroy(ctx, scratch);
        if ( gens ) { secp256k1_bulletproofs_generators_destroy(ctx, gens); }
        return status;
}

signed
main (void) {

    secp256k1_context * ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    unsigned char proof [SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_];
    size_t prooflen = SECP256K1_BULLETPROOFS_RANGEPROOF_UNCOMPRESSED_MAX_LENGTH_;

    unsigned long someval = randomnumber() % UINT_MAX;

    printf("proving that 0 <= %lu < %zu\n", someval, UINT_MAX);

    secp256k1_pedersen_commitment commitment;
    signed res = prove(ctx, someval, &commitment, proof, &prooflen);
    if ( res != EXIT_SUCCESS ) {
        goto cleanup;
    }

    printf("proof created! (%zu bytes large)\nverifying proof\n", prooflen);

    res = verify(ctx, &commitment, proof, prooflen);
    if ( res != EXIT_SUCCESS ) {
        goto cleanup;
    }

    printf("verified!\n");

    cleanup:
        secp256k1_context_destroy(ctx);
}




#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "NTRUEncrypt.h"
#include "param.h"
#include "poly/poly.h"
#include "api.h"
#include "rng/crypto_hash_sha512.h"

/* kem and encryption use a same key gen */
int crypto_kem_keygenerate(
    unsigned char *pk,
    unsigned char *sk)
{
    int64_t     *f, *g, *hntt, *buf, *mem;
    PARAM_SET   *param;


    param   = get_param_set_by_id(TEST_PARAM_SET);

    /* memory for 3 ring elements: f, g and h */
    mem     = malloc (sizeof(int64_t)*param->N * 3);
    buf     = malloc (sizeof(int64_t)*param->N * 2);
    if (!mem || !buf )
    {
        printf("malloc error!\n");
        return -1;
    }

    f       = mem;
    g       = f   + param->N;
    hntt    = g   + param->N;

    keygen(f,g,hntt,buf,param);

    /* pack h into pk */
    pack_ring_element(pk, param, hntt);

    /* pack F into sk */
    pack_ring_element(sk, param, f);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*2);

    free(mem);
    free(buf);

    return 0;
}



int crypto_kem_encapsulate(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk)
{

    PARAM_SET   *param;
    param   = get_param_set_by_id(pk[0]);

    if (param->id!=NTRU_KEM_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    int64_t    *buf, *mem, *hntt, *cpoly, *mpoly;
    mem     = malloc(sizeof(int64_t)*param->N*3);
    buf     = malloc(sizeof(int64_t)*param->N*4);
    hntt    = mem;
    cpoly   = hntt  + param->N;
    mpoly   = cpoly + param->N;

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*4);

    /* pad the message */
    if (pad_msg( mpoly, (char*) ss, CRYPTO_BYTES, param) == -1)
        return -1;


    unpack_ring_element(pk, param, hntt);

    encrypt_kem(mpoly, hntt, cpoly, buf, param);

    pack_ring_element (ct, param, cpoly);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*4);
    free(mem);
    free(buf);

    return 0;
}


int crypto_kem_decapsulate(
    unsigned char       *ss,
    const unsigned char *ct,
    const unsigned char *sk)
{
    PARAM_SET   *param;

    param   =   get_param_set_by_id(ct[0]);
    if (param->id!=NTRU_KEM_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    int64_t    *buf, *mem, *f, *cpoly, *mpoly;
    mem     = malloc(sizeof(int64_t)*param->N*3);
    buf     = malloc(sizeof(int64_t)*param->N*2);
    f       = mem;
    cpoly   = f     + param->N;
    mpoly   = cpoly + param->N;
    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*2);

    unpack_ring_element (ct, param, cpoly);

    unpack_ring_element (sk, param, f);

    decrypt_kem(mpoly, f, cpoly, buf, param);

    recover_msg((char*)ss, mpoly, param);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*2);
    free(mem);
    free(buf);

    return 0;
}


int crypto_kem_keygenerate_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness)
{
    int64_t     *f, *g, *hntt, *buf, *mem;
    PARAM_SET   *param;
    unsigned char *seed;
    unsigned char salt[32] = "KEM_KAT|KEY_GEN|KEM_KAT|KEY_GEN|";

    param   = get_param_set_by_id(TEST_PARAM_SET);

    seed    = malloc(LENGTH_OF_HASH);
    /* memory for 3 ring elements: f, g and h */
    mem     = malloc (sizeof(int64_t)*param->N * 3);
    buf     = malloc (sizeof(int64_t)*param->N * 2);
    if (!mem || !buf || !seed)
    {
        printf("malloc error!\n");
        return -1;
    }


    memcpy(seed,    randomness, 32);
    memcpy(seed+32, salt,       32);
    int i;
    printf("seed:\n");
    for (i=0;i<LENGTH_OF_HASH;i++)
        printf("%c,", seed[i]);
    printf("\n");

    f       = mem;
    g       = f   + param->N;
    hntt    = g   + param->N;
    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    keygen_KAT(f,g,hntt,buf,param,seed);

    /* pack h into pk */
    pack_ring_element(pk, param, hntt);

    /* pack F into sk */
    pack_ring_element(sk, param, f);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*2);
    memset(seed,0, LENGTH_OF_HASH);
    free(mem);
    free(buf);
    free(seed);
    return 0;
}



int crypto_kem_encapsulate_KAT(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk,
    const unsigned char *randomness)
{


    PARAM_SET   *param;
    param   = get_param_set_by_id(pk[0]);

    if (param->id!=NTRU_KEM_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    int64_t    *buf, *mem, *hntt, *cpoly, *mpoly;

    unsigned char *seed;
    unsigned char salt[32] = "KEM_KAT|KEM_ENC|KEM_KAT|KEM_ENC|";

    mem     = malloc(sizeof(int64_t)*param->N*3);
    buf     = malloc(sizeof(int64_t)*param->N*4);
    seed    = malloc(sizeof(unsigned char)*LENGTH_OF_HASH);
    hntt    = mem;
    cpoly   = hntt  + param->N;
    mpoly   = cpoly + param->N;

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*4);


    memcpy(seed,    randomness, 32);
    memcpy(seed+32, salt,       32);

    /* pad the message */
    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    if (pad_msg_KAT( mpoly, (char*) ss, CRYPTO_BYTES, param, seed) == -1)
        return -1;


    unpack_ring_element(pk, param, hntt);

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    encrypt_kem_KAT(mpoly, hntt, cpoly, buf, param, seed);

    pack_ring_element (ct, param, cpoly);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*4);
    memset(seed,0, LENGTH_OF_HASH);
    free(seed);
    free(mem);
    free(buf);

    return 0;
}

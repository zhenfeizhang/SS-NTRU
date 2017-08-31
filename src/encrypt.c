/*
 * encrypt.c
 *
 *  Created on: Aug 31, 2017
 *      Author: zhenfei
 */



#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "api.h"
#include "NTRUEncrypt.h"
#include "rng/crypto_hash_sha512.h"



/* ebacs API: key gen */
int crypto_encrypt_keypair(
    unsigned char       *pk,
    unsigned char       *sk)
{
    int64_t     *f, *g, *hntt, *buf, *mem;
    PARAM_SET   *param;
    param   = get_param_set_by_id(TEST_PARAM_SET);

    /* memory for 3 ring elements: f, g and h */
    mem     = malloc (sizeof(int64_t)*param->N * 3);
    buf     = malloc (sizeof(int64_t)*param->N * 2);
    if (!mem || !buf)
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
    pack_ring_element(sk+param->N*sizeof(int32_t)/sizeof(unsigned char)+1, param, hntt);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*2);

    free(mem);
    free(buf);

    return 0;
}

/* ebacs API: encryption */
int crypto_encrypt(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk)
{
    PARAM_SET   *param;
    param   = get_param_set_by_id(pk[0]);

    if (param->id!=NTRU_CCA_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    int64_t    *buf, *mem, *hntt, *cpoly;
    mem     = malloc(sizeof(int64_t)*param->N*2);
    buf     = malloc(sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    if (!mem || !buf )
    {
        printf("malloc error!\n");
        return -1;
    }

    hntt    = mem;
    cpoly   = hntt  + param->N;


    memset(mem,0, sizeof(int64_t)*param->N*2);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);

    unpack_ring_element(pk, param, hntt);

    encrypt_cca(cpoly, (char*) m, mlen, hntt, buf, param);

    pack_ring_element (c, param, cpoly);

    *clen = param->N*sizeof(int32_t)/sizeof(unsigned char)+1;


    memset(mem,0, sizeof(int64_t)*param->N*2);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    free(mem);
    free(buf);


    return 0;
}

/* ebacs API: decryption */
int crypto_encrypt_open(
    unsigned char       *m,
    unsigned long long  *mlen,
    const unsigned char *c,
    unsigned long long  clen,
    const unsigned char *sk)
{
    PARAM_SET   *param;

    param   =   get_param_set_by_id(c[0]);
    if (param->id!=NTRU_CCA_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    int64_t    *buf, *mem, *f, *cpoly, *mpoly, *hntt;
    mem     = malloc(sizeof(int64_t)*param->N*4);
    buf     = malloc(sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);

    if (!mem || !buf )
    {
        printf("malloc error!\n");
        return -1;
    }

    f       = mem;
    cpoly   = f     + param->N;
    mpoly   = cpoly + param->N;
    hntt    = mpoly + param->N;

    memset(mem,0, sizeof(int64_t)*param->N*4);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);

    unpack_ring_element (c, param, cpoly);

    unpack_ring_element (sk, param, f);

    unpack_ring_element (sk+param->N*sizeof(int32_t)/sizeof(unsigned char)+1, param, hntt);

    *mlen = decrypt_cca((char*) m, f, hntt, cpoly, buf, param);


    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    free(mem);
    free(buf);


    return 0;
}

/* ebacs API: encryption with KAT */
int crypto_encrypt_keypair_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness)
{
    int64_t     *f, *g, *hntt, *buf, *mem;
    PARAM_SET   *param;
    unsigned char *seed;
    unsigned char salt[32] = "CCA_KAT|KEY_GEN|CCA_KAT|KEY_GEN|";

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

    f       = mem;
    g       = f   + param->N;
    hntt    = g   + param->N;


    memcpy(seed,    randomness, 32);
    memcpy(seed+32, salt,       32);
    int i;
    printf("seed:\n");
    for (i=0;i<LENGTH_OF_HASH;i++)
        printf("%c,", seed[i]);
    printf("\n");

    keygen_KAT(f,g,hntt,buf,param,seed);

    /* pack h into pk */
    pack_ring_element(pk, param, hntt);

    /* pack F into sk */
    pack_ring_element(sk, param, f);
    pack_ring_element(sk+param->N*sizeof(int32_t)/sizeof(unsigned char)+1, param, hntt);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*2);
    memset(seed,0, LENGTH_OF_HASH);
    free(mem);
    free(buf);
    free(seed);

    return 0;
}

/* ebacs API: decryption with KAT */
int crypto_encrypt_KAT(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk,
    const unsigned char *randomness)
{

    PARAM_SET   *param;

    param   =   get_param_set_by_id(pk[0]);
    if (param->id!=NTRU_CCA_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    unsigned char *seed;
    unsigned char salt[32] = "CCA_KAT|ENCRYPT|CCA_KAT|ENCRYPT|";

    int64_t    *buf, *mem, *hntt, *cpoly;
    seed    = malloc(LENGTH_OF_HASH);
    mem     = malloc(sizeof(int64_t)*param->N*2);
    buf     = malloc(sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    if (!mem || !buf || !seed )
    {
        printf("malloc error!\n");
        return -1;
    }

    hntt    = mem;
    cpoly   = hntt  + param->N;


    memset(mem,0, sizeof(int64_t)*param->N*2);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);

    unpack_ring_element(pk, param, hntt);

    memcpy(seed,    randomness, 32);
    memcpy(seed+32, salt,       32);

    int i;

    printf("seed:\n");
    for (i=0;i<LENGTH_OF_HASH;i++)
        printf("%c,", seed[i]);
    printf("\n");

    encrypt_cca_KAT(cpoly, (char*) m, mlen, hntt, buf, param, seed);

    pack_ring_element (c, param, cpoly);

    *clen = param->N*sizeof(int32_t)/sizeof(unsigned char)+1;


    memset(mem,0, sizeof(int64_t)*param->N*2);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    memset(seed,0, LENGTH_OF_HASH);
    free(mem);
    free(buf);
    free(seed);
    return 0;
}

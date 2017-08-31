

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "NTRUEncrypt.h"
#include "param.h"
#include "poly/poly.h"
#include "api.h"

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
    if (!mem )
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


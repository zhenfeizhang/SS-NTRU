/*
 * KAT.c
 *
 *  Created on: Aug 31, 2017
 *      Author: zhenfei
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "NTRUEncrypt.h"
#include "param.h"
#include "poly/poly.h"
#include "api.h"
#include "rng/crypto_hash_sha512.h"
/*
 * input a set of parameters, output keys f, g, h
 * requires buffer memory for 2 ring elements
 */
void
keygen_KAT(
          int64_t   *f,       /* output secret key f */
          int64_t   *g,       /* output secret key g */
          int64_t   *hntt,    /* output public key h in NTT form*/
          int64_t   *buf,
    const PARAM_SET *param,
    unsigned char   *seed)
{

    int16_t         i;
    int64_t         *fntt, *gntt;
    fntt = buf;
    gntt = buf+param->N;


    /* sample F and g from discrete Gaussian */

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    DDGS(f,param->N,param->stddev, seed, LENGTH_OF_HASH);

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    DDGS(g,param->N,param->stddev, seed, LENGTH_OF_HASH);

    /* f = 2F+1 */
    for(i=0;i<param->N;i++)
    {
        f[i] = f[i]*2;
    }
    f[0] = f[0]+1;

    /* converting to NTT form */
    NTT(g,gntt,param);
    NTT(f,fntt,param);

    /* compute h = g/f mod q */
    for (i=0;i<param->N;i++)
    {
        /* compute f^-1 mod q */
        fntt[i] = InvMod(fntt[i],param->q);
        /* compute h = gf^-1 mod q */
        hntt[i] = 2*gntt[i]*fntt[i] % param->q;
    }
    memset(buf, 0, sizeof(int64_t)*param->N*2);
}



/* generate a random binary polynomial with degree less than N */

void
binary_poly_gen_KAT(
          int64_t  *f,
    const int16_t  N,
    unsigned char   *seed)
{
    uint16_t r;
    uint64_t i,j,index;
    uint16_t k = 0;
    uint16_t *ptr = (uint16_t*)seed;

    for (i=0;i<=N/16;i++)
    {
        r = ptr[k++];
        if (k==32)
        {
            k=0;
            crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
        }

        for (j=0;j<16;j++)
        {
            index = i*16+j;
            if (index<N)
                f[index] = (r & ( 1 << j)) >> j;
        }
    }
}


/*
 * check if a message length is valid for ntruencrypt-cca
 * then convert the message into a binary polynomial and
 * pad the message with a random binary string p
 */
int
pad_msg_KAT(
          int64_t   *m,     /* output message */
    const char      *msg,   /* input message string */
    const size_t    msg_len,/* input length of the message */
    const PARAM_SET *param,
    unsigned char   *seed)
{
    if (msg_len > param->max_msg_len)
    {
        printf("error: message too long");
        return -1;
    }
    int64_t     *pad;
    uint16_t    i,j;
    char        tmp;
    memset(m, 0, sizeof(int64_t)*param->N);

    /* generate the pad */
    pad =   m + param->N - 256;
    binary_poly_gen_KAT(pad, 256,seed);

    /* form the message binary polynomial */
    for (i=0;i<msg_len;i++)
    {
        tmp = msg[i];
        for(j=0;j<8;j++)
        {
            m[i*8+j] = tmp & 1;
            tmp >>= 1;
        }
    }
    return 0;
}

/*
 * input a message m and a public h, encapsulate m
 * requires buffer memory for 4 ring elements
 */
void
encrypt_kem_KAT(
    const int64_t   *m,     /* input binary message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *cntt,  /* output ciphertext */
          int64_t   *buf,
    const PARAM_SET *param,
    unsigned char   *seed)
{
    uint16_t i;

    /* check message is binary */
    for (i=0;i<param->N;i++)
    {
        if (m[i]!=0 && m[i]!=1)
        {
            printf("invalid messages\n");
            return;
        }
    }

    int64_t *e, *entt, *r, *rntt;
    e    = buf;
    entt = e    +param->N;
    r    = entt +param->N;
    rntt = r    +param->N;

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    DDGS(e,param->N,param->stddev, seed, LENGTH_OF_HASH);
    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    DDGS(r,param->N,param->stddev, seed, LENGTH_OF_HASH);
    for (i=0;i<param->N;i++)
        e[i] = e[i]*2 + m[i];

    NTT(e, entt, param);
    NTT(r, rntt, param);

    for (i=0;i<param->N;i++)
        cntt[i] = modq(rntt[i]*hntt[i]+entt[i], param->q);

    memset(buf, 0, sizeof(int64_t)*param->N*4);

    return;
}


/*
 * CCA-2 secure encryption algorithm using NAEP
 * memory requirement: 7 ring elements + LENGTH_OF_HASH*2
 */
void
encrypt_cca_KAT(
          int64_t   *cntt,  /* output ciphertext */
    const char      *msg,   /* input binary message */
    const size_t    msg_len,/* input - length of the message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *buf,
    const PARAM_SET *param,
    unsigned char   *seed)
{
    uint16_t i;

    int64_t *e, *entt, *r, *rntt, *m, *c;
    int64_t *hashbuf;

    e    = buf;
    entt = e    + param->N;
    r    = entt + param->N;
    rntt = r    + param->N;
    m    = rntt + param->N;
    c    = m    + param->N;
    hashbuf = m + param->N;

    memset (buf, 0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);

    /* pad the message into a ring element */

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    pad_msg_KAT(m, msg, msg_len, param, seed);

    /* generate r from hash(m|h) */
    generate_r(r, m, hntt, hashbuf, param);

    /* c = r*h */
    NTT(r, rntt, param);
    for (i=0;i<param->N;i++)
        cntt[i] = modq(rntt[i]*hntt[i], param->q);

    INTT(c,cntt, param);

    /* mask = hash(c);  m = m \xor mask */
    mask_m(c, m, hashbuf, param);

    /* e <-- DGS; e = 2e + m */
    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    DDGS(e,param->N,param->stddev, seed, LENGTH_OF_HASH);
    for (i=0;i<param->N;i++)
        e[i] = e[i]*2 + m[i];

    NTT(e, entt, param);
    for (i=0;i<param->N;i++)
        cntt[i] = modq(cntt[i]+entt[i], param->q);

    memset(buf, 0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    return;
}

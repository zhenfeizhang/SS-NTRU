/*
 ============================================================================
 Name        : NTRU-KEM.c
 Author      : zhenfei
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "NTRUEncrypt.h"
#include "param.h"
#include "poly/poly.h"


int get_len(char *c)
{
    int len = 0;
    while(c[len]!='\0')
        len++;
    return len;
}

int main(void) {


    uint16_t    i;
    PARAM_SET   *param = get_param_set_by_id(NTRU_KEM_1024);
    int64_t     *mem, *f, *g, *hntt, *buf, *m, *m2,*cntt; /* *c, *h; */
    char        *test_phrase = "this is nist submission";
    char        *msg_rev;
    uint16_t    len;



    mem     = malloc(sizeof(int64_t)*param->N*13+LENGTH_OF_HASH*2);
    msg_rev = malloc(sizeof(char)*param->max_msg_len);
    if (!mem|| !msg_rev)
    {
        printf("malloc failed\n");
        return -1;
    }

    m       = mem;
    m2      = m     + param->N;
    cntt    = m2    + param->N;
    f       = cntt  + param->N;
    g       = f     + param->N;;
    hntt    = g     + param->N;
    buf     = hntt  + param->N;     /* 7 ring elements and 2 hashes*/

    len     = get_len(test_phrase);

    printf("============================================\n");
    printf("basic functionalities \n");


    printf("testing discrete Gaussian sampler with dev %lld\n", (long long) param->stddev);
    DGS(f,param->N,param->stddev);
    for(i=0;i<param->N;i++)
    {
        printf("%5lld ", (long long) f[i]);
        if (i%32==31)
            printf("\n");
    }
    memset(f, 0, sizeof(int64_t)*param->N);
    /* deterministic DGS */
    printf("testing deterministic discrete Gaussian sampler with dev %lld\n", (long long) param->stddev);
    DDGS ( hntt,param->N, param->stddev, (unsigned char *)f, 128);

    for(i=0;i<1024;i++)
    {
        printf("%5lld ", (long long) hntt[i]);
        if (i%32==31)
            printf("\n");
    }
    memset(hntt, 0, sizeof(int64_t)*param->N);

    printf("============================================\n");
    printf("============================================\n");

    printf("testing key gen\n");

    keygen(f, g, hntt, buf, param);

    printf("f:\n");
    for(i=0;i<param->N;i++)
    {
        printf("%5lld,", (long long) f[i]);
        if (i%32==31)
            printf("\n");
    }

    printf("g:\n");
    for(i=0;i<param->N;i++)
    {
        printf("%5lld,", (long long) g[i]);
        if (i%32==31)
            printf("\n");
    }

    printf("h (in NTT form):\n");
    for(i=0;i<param->N;i++)
    {
        printf("%10lld,",(long long)  hntt[i]);
        if (i%16==15)
            printf("\n");
    }

    printf("check keys, 0 - okay, -1 - error: %d\n", check_keys(f, g, hntt, buf, param));


    printf("============================================\n");
    printf("============================================\n");
    printf("now testing KEM.\n");

    printf("generate a random binary polynomial as the message\n");
    binary_poly_gen(m, param->N);

    for(i=0;i<param->N;i++)
    {
        printf("%2lld ", (long long) m[i]);
        if (i%32==31)
            printf("\n");
    }
    printf("now encrypt/encapsulate m into a ciphertext c (in NTT form)\n");
    encrypt_kem(m, hntt, cntt, buf, param);

    for(i=0;i<param->N;i++)
    {
        printf("%10lld ",(long long)  cntt[i]);
        if (i%16==15)
            printf("\n");
    }

    printf("at last we decrypt c to recover m\n");
    decrypt_kem(m2, f, cntt, buf, param);


    int counter = 0;
    for(i=0;i<param->N;i++)
    {
        counter += abs(m2[i]-m[i]);
        printf("%2lld ", (long long)  m2[i]);
        if (i%32==31)
            printf("\n");
    }
    printf("there are %d out of 1024 coefficients that are incorrect!\n", counter);
    printf("============================================\n");
    printf("============================================\n");
    printf("now testing CCA-2 encryption.\n");
    printf("now lets try to encrypt a string of %d characters: \"nist submission\"\n", len);



    encrypt_cca(cntt, test_phrase, len, hntt, buf, param);

    printf("the ciphertext for \"%s\" is:  (in NTT form)\n", test_phrase);

    for(i=0;i<param->N;i++)
    {
        printf("%10lld ",(long long)  cntt[i]);
        if (i%16==15)
            printf("\n");
    }


    len = decrypt_cca(msg_rev, f,hntt, cntt, buf, param);
    printf("decrypting this ciphertext we get a msg with length %d chars: ", len);
    for (i=0;i<len;i++)
        printf("%c", msg_rev[i]);
    printf("\n");

    printf("!!!Hello OnBoard Security!!!\n"); /* prints !!!Hello OnBoard Security!!! */
    free(mem);
    return EXIT_SUCCESS;
}

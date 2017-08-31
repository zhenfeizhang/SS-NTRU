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
#include "api.h"


unsigned char   rndness[32] = "source of randomness";
unsigned char   msg[32]     = "nist submission";

int get_len(char *c)
{
    int len = 0;
    while(c[len]!='\0')
        len++;
    return len;
}

int test_basics(void) {


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

void test_nist_api_kem()
{
    printf("===============================\n");
    printf("===============================\n");
    printf("===============================\n");
    printf("testing NIST KEM API\n");

    int     i;
    unsigned char       *m, *c, *mr;
    unsigned char       *pk, *sk;


    pk  = malloc(sizeof(unsigned char)* 4200*2);
    sk  = malloc(sizeof(unsigned char)* 4200*2);
    m   = malloc(sizeof(unsigned char)* 4200*2);
    c   = malloc(sizeof(unsigned char)* 4200*2);
    mr  = malloc(sizeof(unsigned char)* 4200*2);

    printf("Let's try to encrypt a message:\n");
    for(i=0;i<32; i++)
    {
        m[i] = rand();
        printf("%d, ", m[i]);
    }
    printf("\n");



    crypto_kem_keygenerate(pk, sk);


    crypto_kem_encapsulate(c, m, pk);


    crypto_kem_decapsulate(mr, c, sk);

    printf("recovered message: \n" );
    for(i=0;i< 32; i++)
        printf("%d, ", mr[i]);
    printf("\n");


    free(pk);
    free(sk);
    free(m);
    free(c);
    free(mr);
    puts("!!!Hello OnBoard Security!!!");

}

void test_nist_api_kem_KAT()
{
    printf("===============================\n");
    printf("===============================\n");
    printf("===============================\n");
    printf("testing NIST KEM API with KAT\n");

    int     i;
    unsigned char       *m, *c, *mr;
    unsigned char       *pk, *sk;


    pk  = malloc(sizeof(unsigned char)* 4200*2);
    sk  = malloc(sizeof(unsigned char)* 4200*2);
    m   = malloc(sizeof(unsigned char)* 4200*2);
    c   = malloc(sizeof(unsigned char)* 4200*2);
    mr  = malloc(sizeof(unsigned char)* 4200*2);

    printf("Let's try to encrypt a message:\n");
    for(i=0;i<32; i++)
    {
        m[i] = rand();
        printf("%d, ", m[i]);
    }
    printf("\n");



    crypto_kem_keygenerate_KAT(pk, sk, rndness);
    printf("the first 32 bytes of public key are : \n" );
    for(i=0;i< 32; i++)
        printf("%d, ", pk[i]);
    printf("\n");
    printf("the first 32 bytes of secret key are : \n" );
    for(i=0;i< 32; i++)
        printf("%d, ", sk[i]);
    printf("\n");

    crypto_kem_encapsulate_KAT(c, m, pk,rndness);

    printf("the first 32 bytes of ciphertext are : \n" );
    for(i=0;i< 32; i++)
        printf("%d, ", c[i]);
    printf("\n");
    crypto_kem_decapsulate(mr, c, sk);

    printf("recovered message: \n" );
    for(i=0;i< 32; i++)
        printf("%d, ", mr[i]);
    printf("\n");


    free(pk);
    free(sk);
    free(m);
    free(c);
    free(mr);
    puts("!!!Hello OnBoard Security!!!");

}

void test_nist_api_cca()
{
    printf("===============================\n");
    printf("===============================\n");
    printf("===============================\n");
    printf("testing NIST CCA API\n");

    int     i;
    unsigned char       *m, *c, *mr;
    unsigned char       *pk, *sk;
    unsigned long long  msg_len, c_len;

    pk  = malloc(sizeof(unsigned char)* 4200*2);
    sk  = malloc(sizeof(unsigned char)* 4200*2);
    m   = malloc(sizeof(unsigned char)* 4200*2);
    c   = malloc(sizeof(unsigned char)* 4200*2);
    mr  = malloc(sizeof(unsigned char)* 4200*2);

    printf("Let's try to encrypt a message: %s\n", msg);

    crypto_encrypt_keypair(pk, sk);
    printf("key generated, public key:\n");

    msg_len = get_len((char*)msg);
    crypto_encrypt(c, &c_len,  msg, msg_len, pk);
    printf("encryption complete, ciphtertext of length %d:\n", (int) c_len);
    for (i=0;i<c_len;i++)
        printf("%d, ", (int)c[i]);
    printf("\n");


    msg_len = 0;
    crypto_encrypt_open(m, &msg_len, c, c_len, sk);

    printf("recovered message with length %d: %s\n", (int)msg_len, m );

    free(pk);
    free(sk);
    free(m);
    free(c);
    free(mr);
    puts("!!!Hello OnBoard Security!!!");
}



void test_nist_api_cca_KAT()
{
    printf("===============================\n");
    printf("===============================\n");
    printf("===============================\n");
    printf("testing NIST CCA API with KAT\n");

    int     i;
    unsigned char       *m, *c, *mr;
    unsigned char       *pk, *sk;
    unsigned long long  msg_len, c_len;

    pk  = malloc(sizeof(unsigned char)* 4200*2);
    sk  = malloc(sizeof(unsigned char)* 4200*2);
    m   = malloc(sizeof(unsigned char)* 4200*2);
    c   = malloc(sizeof(unsigned char)* 4200*2);
    mr  = malloc(sizeof(unsigned char)* 4200*2);

    printf("Let's try to encrypt a message: %s\n", msg);

    crypto_encrypt_keypair_KAT(pk, sk, rndness);
    printf("key generated\n");
    printf("the first 32 bytes of public key are : \n" );
    for(i=0;i< 32; i++)
        printf("%d, ", pk[i]);
    printf("\n");
    printf("the first 32 bytes of secret key are : \n" );
    for(i=0;i< 32; i++)
        printf("%d, ", sk[i]);
    printf("\n");

    msg_len = get_len((char*)msg);
    crypto_encrypt_KAT(c, &c_len,  msg, msg_len, pk, rndness);
    printf("encryption complete, first 32 bytes of ciphtertext of length %d:\n", (int) c_len);
    for (i=0;i<32;i++)
        printf("%d, ", (int)c[i]);
    printf("\n");


    msg_len = 0;
    crypto_encrypt_open(m, &msg_len, c, c_len, sk);

    printf("recovered message with length %d: %s\n", (int)msg_len, m );

    free(pk);
    free(sk);
    free(m);
    free(c);
    free(mr);
    puts("!!!Hello OnBoard Security!!!");
}


int main()
{
    test_basics();
    if (TEST_PARAM_SET == NTRU_CCA_1024)
        test_nist_api_cca();
    else
        test_nist_api_kem();

    if (TEST_PARAM_SET == NTRU_CCA_1024)
        test_nist_api_cca_KAT();
    else
        test_nist_api_kem_KAT();
}

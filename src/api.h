/*
 * api.h
 *
 *  Created on: Aug 29, 2017
 *      Author: zhenfei
 */

#ifndef API_H_
#define API_H_

#define TEST_SS_NTRU_CCA




#ifdef TEST_SS_NTRU_CCA
    #define TEST_PARAM_SET  NTRU_CCA_1024
    #define CRYPTO_SECRETKEYBYTES 700   /* secret key length */
    #define CRYPTO_PUBLICKEYBYTES 610   /* public key length */
    #define CRYPTO_BYTES 32             /* padding ? */
    #define CRYPTO_RANDOMBYTES 32       /* random input */
#endif



#ifdef TEST_SS_NTRU_KEM
    #define TEST_PARAM_SET  NTRU_KEM_1024
    #define CRYPTO_SECRETKEYBYTES 4097  /* secret key length */
    #define CRYPTO_PUBLICKEYBYTES 4097  /* public key length */
    #define CRYPTO_BYTES 32             /* shared secret length */
    #define CRYPTO_CIPHERTEXTBYTES 4097
    #define CRYPTO_RANDOMBYTES 32       /* random input */
#endif


/* ebacs API: key gen */
int crypto_encrypt_keypair(
    unsigned char       *pk,
    unsigned char       *sk);

/* ebacs API: encryption */
int crypto_encrypt(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk);

/* ebacs API: decryption */
int crypto_encrypt_open(
    unsigned char       *m,
    unsigned long long  *mlen,
    const unsigned char *c,
    unsigned long long  clen,
    const unsigned char *sk);

/* ebacs API: encryption with KAT */
int crypto_encrypt_keypair_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness);

/* ebacs API: decryption with KAT */
int crypto_encrypt_KAT(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk,
    const unsigned char *randomness);


int crypto_kem_keygenerate(
    unsigned char       *pk,
    unsigned char       *sk);

int crypto_kem_encapsulate(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk);

int crypto_kem_decapsulate(
    unsigned char       *ss,
    const unsigned char *ct,
    const unsigned char *sk);

int crypto_kem_keygenerate_KAT(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *randomness);

int crypto_kem_encapsulate_KAT(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk,
    const unsigned char *randomness);

#endif /* API_H_ */

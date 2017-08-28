/*
 * NTRUEncrypt.h
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */

#ifndef NTRUENCRYPT_H_
#define NTRUENCRYPT_H_

#include "param.h"


/*
 * input a set of parameters, output keys f, g, h
 * requires buffer memory for 2 ring elements
 */
void
keygen(
          int64_t     *f,       /* output secret key f */
          int64_t     *g,       /* output secret key g */
          int64_t     *hntt,    /* output public key h in NTT form*/
          int64_t     *buf,
    const PARAM_SET   *param);

/*
 * optional, check the correctness of the keys;
 * requires buffer memory for 2 ring elements
 */
int
check_keys(
    const int64_t   *f,
    const int64_t   *g,
    const int64_t   *hntt,
          int64_t   *buf,
    const PARAM_SET *param);

/*
 * input a message m and a public h, encapsulate m
 * requires buffer memory for 4 ring elements
 */
void
encrypt_kem(
    const int64_t   *m,     /* input binary message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *cntt,  /* output ciphertext */
          int64_t   *buf,
    const PARAM_SET *param);

/*
 * decapsulation function;
 * memory requirements: 2 ring elements;
 */
void
decrypt_kem(
          int64_t   *m,     /* output binary message */
    const int64_t   *f,     /* input secret key */
    const int64_t   *cntt,  /* input ciphertext */
          int64_t   *buf,
    const PARAM_SET *param);

/*
 * CCA-2 secure encryption algorithm using NAEP
 * memory requirement: 7 ring elements + LENGTH_OF_HASH*2
 */
void
encrypt_cca(
          int64_t   *cntt,  /* output ciphertext */
    const char      *msg,   /* input binary message */
    const size_t    msg_len,/* input - length of the message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *buf,
    const PARAM_SET *param);

/*
 * CCA-2 secure decryption algorithm using NAEP
 * memory requirement: 7 ring elements + LENGTH_OF_HASH*2
 */
int decrypt_cca(
          char      *msg,   /* output message string */
    const int64_t   *f,     /* input secret key */
    const int64_t   *hntt,  /* input public key */
    const int64_t   *cntt,  /* input ciphertext */
          int64_t   *buf,
    const PARAM_SET *param);

#endif /* NTRUENCRYPT_H_ */

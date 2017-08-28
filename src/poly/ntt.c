/*
 * ntt.c
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntt.h"
#include "../param.h"


int64_t modq(
          int64_t     a,
          int64_t     q)
{
    int64_t     b = a%q;
    if (b<0)
        return q+b;
    else
        return b;
}

void INTT(
          int64_t     *f,
    const int64_t     *f_ntt,
    const PARAM_SET    *param)
{
    uint16_t    i,j;
    int64_t     base;

    memset(f, 0, sizeof(int64_t)*param->N);
    for (j=0;j<param->N;j++)
    {
        base = 1;
        for (i=0;i<param->N;i++)
        {

            f[i] = modq(f[i]+f_ntt[j]*base,param->q);
            base = modq(base*inv_roots[j], param->q);
        }
    }
    for (i=0;i<param->N;i++)
    {
        f[i] = modq(f[i]*one_over_N,param->q);
        if(f[i]>param->q/2)
            f[i] = f[i]-param->q;
    }

}


void NTT(
    const int64_t     *f,
          int64_t     *f_ntt,
    const PARAM_SET    *param)
{
    uint16_t    i,j;
    int64_t     odd,even, base;
    int64_t     tmp;

    for (i=0;i<param->N/2;i++)
    {
        odd  = f[0];
        even = f[0];
        base = 1;
        for (j=1;j<param->N;j++)
        {
            base = base*roots[i];
            base = modq(base,param->q);

            tmp = modq(f[j],param->q)*base;
            tmp = modq(tmp, param->q);

            even = even + tmp;
            if (j%2==0)
                odd = odd + tmp;
            else
                odd = odd + param->q - tmp;
        }
        f_ntt[i]= modq(even, param->q);
        f_ntt[param->N-1-i] = modq(odd, param->q);
    }
}

int64_t* extendedEuclid (int64_t a, int64_t b)
{
    int64_t *dxy = (int64_t *)malloc(sizeof(int64_t) *3);

    if (b ==0){
        dxy[0] =a; dxy[1] =1; dxy[2] =0;

        return dxy;
    }
    else{
        int64_t t, t2;
        dxy = extendedEuclid(b, (a %b));
        t =dxy[1];
        t2 =dxy[2];
        dxy[1] =dxy[2];
        dxy[2] = t - a/b *t2;

        return dxy;
    }
}

int64_t InvMod(int64_t a, int64_t n)
{
   int64_t *ptr;

   ptr = extendedEuclid (a,n);
   if (ptr[0]!=1 && ptr[0]!=-1)
       printf("error\n");

   if (ptr[0] == -1)
       ptr[1] = -ptr[1];
   if (ptr[1] < 0)
      return ptr[1] + n;
   else
      return ptr[1];
}



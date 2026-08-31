#ifndef TOY_CRYPTO_H
#define TOY_CRYPTO_H

#include "params.h"

void keygen(int s[]);
void encrypt(int s[], int u[], int *v, int message, int *noise_out);
void partial_decrypt(int share_vector[], int u[], int *result);

#endif

#include <stdlib.h>
#include "params.h"
#include "toy_crypto.h"

static int mod(int a) {
    int r = a % Q;
    return (r < 0) ? r + Q : r;
}

void keygen(int s[]) {
    for (int i = 0; i < VECTOR_DIM; i++)
        s[i] = rand() % Q;
}

void encrypt(int s[], int u[], int *v, int message, int *noise_out) {
    int dot = 0;

    for (int i = 0; i < VECTOR_DIM; i++) {
        u[i] = rand() % Q;
        dot = mod(dot + s[i] * u[i]);
    }

    int noise = (rand() % (2 * NOISE_BOUND)) - NOISE_BOUND;
    *noise_out = noise;

    *v = mod(dot + noise + message);
}

void partial_decrypt(int share_vector[], int u[], int *result) {
    int dot = 0;

    for (int i = 0; i < VECTOR_DIM; i++)
        dot = mod(dot + share_vector[i] * u[i]);

    *result = mod(-dot);
}

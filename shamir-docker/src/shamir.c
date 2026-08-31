#include <stdlib.h>
#include "params.h"
#include "shamir.h"
#include "lagrange.h"

static int mod(int a) {
    int r = a % Q;
    return (r < 0) ? r + Q : r;
}

void shamir_split(int secret, int shares[][2], int k, int n) {
    int coeffs[k];
    coeffs[0] = mod(secret);

    for (int i = 1; i < k; i++)
        coeffs[i] = rand() % Q;

    for (int i = 0; i < n; i++) {
        int x = i + 1;
        int y = 0;
        int power = 1;

        for (int j = 0; j < k; j++) {
            y = mod(y + coeffs[j] * power);
            power = mod(power * x);
        }

        shares[i][0] = x;
        shares[i][1] = y;
    }
}

int shamir_reconstruct(int shares[][2], int k) {
    return lagrange_interpolate_zero(shares, k);
}

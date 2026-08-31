#include "params.h"

static int mod(int a) {
    int r = a % Q;
    return (r < 0) ? r + Q : r;
}

static int mod_inverse(int a) {
    int t = 0, newt = 1;
    int r = Q, newr = mod(a);

    while (newr != 0) {
        int q = r / newr;

        int temp = t;
        t = newt;
        newt = temp - q * newt;

        temp = r;
        r = newr;
        newr = temp - q * newr;
    }

    if (r > 1) return -1;
    return mod(t);
}

int lagrange_interpolate_zero(int shares[][2], int k) {
    int result = 0;

    for (int i = 0; i < k; i++) {
        int xi = shares[i][0];
        int yi = shares[i][1];

        int num = 1;
        int den = 1;

        for (int j = 0; j < k; j++) {
            if (j == i) continue;

            int xj = shares[j][0];
            num = mod(num * (-xj));
            den = mod(den * (xi - xj));
        }

        int inv = mod_inverse(den);
        int term = mod(yi * num);
        term = mod(term * inv);

        result = mod(result + term);
    }

    return result;
}

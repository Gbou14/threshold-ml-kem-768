#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "params.h"
#include "toy_crypto.h"
#include "shamir.h"

int main() {

    srand(time(NULL));

    FILE *fp = fopen("data/results.csv", "w");
    fprintf(fp, "noise,recovered,distance,success\n");

    int s[VECTOR_DIM];
    keygen(s);

    int shares[N_PARTIES][VECTOR_DIM][2];

    for (int d = 0; d < VECTOR_DIM; d++) {
        int temp[N_PARTIES][2];
        shamir_split(s[d], temp, THRESHOLD, N_PARTIES);

        for (int i = 0; i < N_PARTIES; i++) {
            shares[i][d][0] = temp[i][0];
            shares[i][d][1] = temp[i][1];
        }
    }

    for (int trial = 0; trial < 200; trial++) {

        int u[VECTOR_DIM];
        int v;
        int noise;
        int message = 1;

        encrypt(s, u, &v, message, &noise);

        int partials[THRESHOLD][2];

        for (int i = 0; i < THRESHOLD; i++) {

            int share_vector[VECTOR_DIM];

            for (int d = 0; d < VECTOR_DIM; d++)
                share_vector[d] = shares[i][d][1];

            int partial;
            partial_decrypt(share_vector, u, &partial);

            partials[i][0] = shares[i][0][0];
            partials[i][1] = partial;
        }

        int combined = shamir_reconstruct(partials, THRESHOLD);
        int recovered = (v + combined) % Q;

/* RESEARCH METRIC 1:
   Distance from correct message */
int distance = recovered - message;
if (distance < 0) distance = -distance;

int success = (recovered == message);

fprintf(fp, "%d,%d,%d,%d\n",
        noise,
        recovered,
        distance,
        success);

    }

    fclose(fp);
    printf("Experiment complete.\n");

    return 0;
}

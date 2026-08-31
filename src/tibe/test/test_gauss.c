/*
 * Self-contained regression test for the Gaussian-sampling module.
 * gauss_sample_coeff is a *practical approximation* of a discrete
 * Gaussian (continuous Box-Muller, rounded to nearest integer -- see
 * ../README.md "Gaussian sampling"), so this validates it by empirical
 * statistics, not by matching a formal discrete-Gaussian reference
 * (none is pinned anywhere in this project): mean should be near 0,
 * and the empirical standard deviation should land close to the
 * requested sigma, for every width this project actually uses
 * (TIBE_SIGMA, TIBE_SIGMA_A, TIBE_SIGMA_P).
 */
#include <math.h>
#include <stdio.h>

#include "../gauss.h"
#include "../params.h"

static int failures = 0;

#define CHECK(cond, msg)                                                                                             \
    do                                                                                                                \
    {                                                                                                                 \
        if (!(cond))                                                                                                  \
        {                                                                                                             \
            printf("FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__);                                                    \
            failures++;                                                                                               \
        }                                                                                                             \
    } while (0)

static void
check_stats(double sigma, int n, double mean_tol_sigmas, double stddev_tol_frac)
{
    double sum = 0.0;
    double sum_sq = 0.0;
    for (int i = 0; i < n; i++)
    {
        double v = (double)gauss_sample_coeff(sigma);
        sum += v;
        sum_sq += v * v;
    }
    double mean = sum / n;
    double variance = sum_sq / n - mean * mean;
    double stddev = sqrt(variance);

    printf("  sigma=%.3g: n=%d empirical mean=%.4g empirical stddev=%.4g\n", sigma, n, mean, stddev);

    char msg[256];
    snprintf(msg, sizeof(msg), "sigma=%.3g: |mean| within %.1f*sigma of 0", sigma, mean_tol_sigmas);
    CHECK(fabs(mean) < mean_tol_sigmas * sigma, msg);

    snprintf(msg, sizeof(msg), "sigma=%.3g: empirical stddev within %.0f%% of sigma", sigma, stddev_tol_frac * 100.0);
    CHECK(fabs(stddev - sigma) < stddev_tol_frac * sigma, msg);
}

int
main(void)
{
    /* Every width this project's Table 2 instantiation actually needs
     * (params.h): the TIBE master secret's width, the TIBE encryption
     * randomness width, and the (huge) per-shareholder blinding width.
     * 20000 samples keeps the empirical-stddev estimate's own standard
     * error comfortably under the 10% tolerance used below. */
    check_stats(TIBE_SIGMA_A, 20000, 0.05, 0.10);
    check_stats(TIBE_SIGMA, 20000, 0.05, 0.10);
    check_stats(TIBE_SIGMA_P, 20000, 0.05, 0.10);

    if (failures == 0)
    {
        printf("test_gauss: all tests passed\n");
        return 0;
    }
    printf("test_gauss: %d failure(s)\n", failures);
    return 1;
}

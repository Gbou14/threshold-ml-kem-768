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
#include <string.h>

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

static void
check_prg_stats(double sigma, int n, double mean_tol_sigmas, double stddev_tol_frac)
{
    /* Same statistical check as check_stats above, but through the
     * deterministic gauss_prg path (tkem.c's derandomized Encaps) --
     * a fixed seed here, since the point is validating the
     * distribution the PRG-driven sampler produces, not testing
     * seed-dependent determinism (that's covered by test_tkem.c's
     * re-encryption check reproducing the exact same ciphertext). */
    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));
    gauss_prg prg;
    gauss_prg_init(&prg, seed, sizeof(seed), (size_t)n * 16);

    double sum = 0.0;
    double sum_sq = 0.0;
    for (int i = 0; i < n; i++)
    {
        double v = (double)gauss_sample_coeff_from_prg(&prg, sigma);
        sum += v;
        sum_sq += v * v;
    }
    gauss_prg_free(&prg);

    double mean = sum / n;
    double variance = sum_sq / n - mean * mean;
    double stddev = sqrt(variance);

    printf("  [prg] sigma=%.3g: n=%d empirical mean=%.4g empirical stddev=%.4g\n", sigma, n, mean, stddev);

    char msg[256];
    snprintf(msg, sizeof(msg), "[prg] sigma=%.3g: |mean| within %.1f*sigma of 0", sigma, mean_tol_sigmas);
    CHECK(fabs(mean) < mean_tol_sigmas * sigma, msg);

    snprintf(msg, sizeof(msg), "[prg] sigma=%.3g: empirical stddev within %.0f%% of sigma", sigma,
             stddev_tol_frac * 100.0);
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

    /* The PRG-driven path only actually needs TIBE_SIGMA/TIBE_SIGMA_PRIME
     * (tkem.c's derandomized TIBE.Encrypt) -- checked at TIBE_SIGMA here
     * as a representative width, not all three, since it's the same
     * Box-Muller core already validated above with a different entropy
     * source. */
    check_prg_stats(TIBE_SIGMA, 20000, 0.05, 0.10);

    if (failures == 0)
    {
        printf("test_gauss: all tests passed\n");
        return 0;
    }
    printf("test_gauss: %d failure(s)\n", failures);
    return 1;
}

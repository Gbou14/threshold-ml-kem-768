/*
 * Self-contained regression test for the Gaussian-sampling module.
 * Since Phase 8b, gauss_sample_coeff is an *exact* discrete Gaussian
 * (CDT for the small widths, Micciancio-Walter convolution for the
 * two huge ones -- see ../README.md "Gaussian sampling"), but there is
 * still no external reference to diff against (none is pinned anywhere
 * in this project, nor does one exist for this exact parameter set),
 * so this validates it the same way the prior Box-Muller version was
 * validated: empirical statistics (mean near 0, empirical standard
 * deviation close to the requested sigma) for every width this
 * project actually uses (TIBE_SIGMA, TIBE_SIGMA_A, TIBE_SIGMA_PRIME,
 * TIBE_SIGMA_P), plus a direct comparison of the small-width CDT
 * tables against their theoretical PMF (feasible now that sampling is
 * exact, unlike Box-Muller).
 */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
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
    gauss_prg_init(&prg, seed, sizeof(seed), (size_t)n * gauss_bytes_per_coeff(sigma));

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

/* Since Phase 8b's sampler is exact (not Box-Muller's continuous
 * approximation), it can be checked against the actual theoretical
 * discrete-Gaussian PMF, not just mean/stddev -- an independent
 * cross-check (plain double-precision exp() here vs. the sampler's own
 * BIGNUM fixed-point exp()) that a mean/stddev match alone wouldn't
 * catch (e.g. a table that's symmetric and has the right variance but
 * the wrong shape). Only meaningful for the direct-CDT widths (a
 * convolution-built huge-sigma sample is a sum of many table draws,
 * not one table lookup, so there's no single table to compare a
 * histogram against here). Bins with expected count < 20 are skipped
 * (too few samples for a meaningful per-bin check at any width this
 * project uses without an impractically large n). */
static void
check_pmf(double sigma, int n)
{
    int half_range = (int)(4 * sigma); /* covers >99.993% of the mass */
    int nbins = 2 * half_range + 1;
    long* counts = calloc((size_t)nbins, sizeof(long));

    /* theoretical Z normalizes over the *full* tail (+-20*sigma is
     * indistinguishable from the true infinite sum at double
     * precision), matching what the sampler's own tau=15 cutoff
     * approximates far more precisely (see gauss.c). */
    double z = 0.0;
    for (int k = -20 * (int)sigma; k <= 20 * (int)sigma; k++)
    {
        z += exp(-((double)k * k) / (2.0 * sigma * sigma));
    }

    for (int i = 0; i < n; i++)
    {
        int64_t v = gauss_sample_coeff(sigma);
        if (v >= -half_range && v <= half_range)
        {
            counts[v + half_range]++;
        }
    }

    int checked = 0;
    double max_rel_err = 0.0;
    for (int b = 0; b < nbins; b++)
    {
        int k = b - half_range;
        double p = exp(-((double)k * k) / (2.0 * sigma * sigma)) / z;
        double expected = p * n;
        if (expected < 20.0)
        {
            continue;
        }
        double empirical = (double)counts[b];
        double stderr_est = sqrt(expected * (1.0 - p));
        double rel_err = fabs(empirical - expected) / stderr_est;
        if (rel_err > max_rel_err)
        {
            max_rel_err = rel_err;
        }
        checked++;
    }
    printf("  [pmf] sigma=%.3g: n=%d, %d bins checked, max deviation %.2f standard errors\n", sigma, n, checked,
           max_rel_err);

    char msg[256];
    snprintf(msg, sizeof(msg), "sigma=%.3g: PMF matches theoretical discrete Gaussian within 6 standard errors",
              sigma);
    CHECK(checked > 0 && max_rel_err < 6.0, msg);

    free(counts);
}

int
main(void)
{
    /* Every width this project's Table 2 instantiation actually needs
     * (params.h). 20000 samples for the direct-CDT small widths keeps
     * the empirical-stddev estimate's own standard error comfortably
     * under the 10% tolerance used below; the two huge (convolution-
     * built) widths use fewer samples purely for runtime -- each
     * single sample there costs up to ~2^levels CDT table lookups
     * (gauss.c), not one. */
    check_stats(TIBE_SIGMA_A, 20000, 0.05, 0.10);
    check_stats(TIBE_SIGMA, 20000, 0.05, 0.10);
    check_stats(TIBE_SIGMA_PRIME, 5000, 0.05, 0.10);
    check_stats(TIBE_SIGMA_P, 5000, 0.05, 0.10);

    /* The PRG-driven path is what tkem.c's derandomized TIBE.Encrypt
     * actually uses, at TIBE_SIGMA and TIBE_SIGMA_PRIME specifically
     * (tibe.c's tibe_encrypt_derand) -- check both, not just one, since
     * TIBE_SIGMA_PRIME's convolution schedule is genuinely different
     * code from TIBE_SIGMA's direct path. */
    check_prg_stats(TIBE_SIGMA, 20000, 0.05, 0.10);
    check_prg_stats(TIBE_SIGMA_PRIME, 5000, 0.05, 0.10);

    /* Exact-PMF cross-check, direct-CDT widths only (see check_pmf's
     * comment). */
    check_pmf(TIBE_SIGMA, 200000);
    check_pmf(TIBE_SIGMA_A, 200000);

    if (failures == 0)
    {
        printf("test_gauss: all tests passed\n");
        return 0;
    }
    printf("test_gauss: %d failure(s)\n", failures);
    return 1;
}

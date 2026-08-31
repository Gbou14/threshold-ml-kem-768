/*
 * ML-KEM-768 (Kyber, k=3) protocol parameters, as fixed by FIPS 203.
 *
 * These are public numeric constants defined by the standard, not a design
 * choice of this codebase -- any conformant implementation uses the same
 * values.
 */
#ifndef KYBER_PARAMS_H
#define KYBER_PARAMS_H

#define KYBER_N 256   /* ring dimension: R_q = Z_q[X]/(X^N + 1)          */
#define KYBER_Q 3329  /* modulus                                          */
#define KYBER_K 3     /* module rank (768 = 256 * 3)                      */

#define KYBER_ETA1 2 /* noise width for secret/error vectors in KeyGen/Enc */
#define KYBER_ETA2 2 /* noise width for the extra encryption-time error    */

#define KYBER_SYMBYTES 32 /* size of seeds / hash outputs, in bytes        */
#define KYBER_MSGBYTES 32 /* size of the encapsulated message, in bytes    */

#define KYBER_POLYBYTES 384 /* bytes to serialize one uncompressed poly (12 bits/coeff) */

/* Ciphertext-compression precision: du bits per coefficient for the
 * vector part, dv bits per coefficient for the scalar part. */
#define KYBER_DU 10
#define KYBER_DV 4

#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * KYBER_N * KYBER_DU / 8)
#define KYBER_POLYCOMPRESSEDBYTES (KYBER_N * KYBER_DV / 8)

#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

#define KYBER_INDCPA_MSGBYTES KYBER_MSGBYTES
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES KYBER_POLYVECBYTES
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)

#endif /* KYBER_PARAMS_H */

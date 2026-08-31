#ifndef SHAMIR_H
#define SHAMIR_H

void shamir_split(int secret, int shares[][2], int k, int n);
int shamir_reconstruct(int shares[][2], int k);

#endif

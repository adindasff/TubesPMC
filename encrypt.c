#include "crypto_aead.h"
#include "romulus_m.h"
#include <stdio.h>
#include <string.h>
#define CRYPTO_BYTES 32

int crypto_aead_encrypt (
			 unsigned char* c, unsigned long long* clen,
			 const unsigned char* m, unsigned long long mlen,
			 const unsigned char* ad, unsigned long long adlen,
			 const unsigned char* nsec,
			 const unsigned char* npub,
			 const unsigned char* k
			 )
{
  return romulus_m_encrypt(c,clen,m,mlen,ad,adlen,nsec,npub,k);
}

int encrypt() {
    char pl[CRYPTO_BYTES];
    printf("Plaintext: ");
    scanf("%s", pl);
    
    unsigned char c[CRYPTO_BYTES];  // Output ciphertext buffer
    unsigned long long clen;  // Length of the ciphertext
    
    const unsigned char* m = (const unsigned char*)pl;  // Input plaintext
    unsigned long long mlen = strlen((const char*)m);  // Length of the plaintext
    
    const unsigned char* ad = NULL;  // No additional data
    unsigned long long adlen = 0;  // Length of the additional data
    
    const unsigned char* nsec = NULL;  // Non-secret value
    const unsigned char* npub = (const unsigned char*)"000000000000111111111111";
    const unsigned char* k = (const unsigned char*)"0123456789ABCDEF0123456789ABCDEF";
    
    crypto_aead_encrypt(c, &clen, m, mlen, ad, adlen, nsec, npub, k);
    printf("Ciphertext: ");
    for (unsigned long long i = 0; i < clen; i++) {
        printf("%02X", c[i]);
    }
    
    return 0;
}

#include "crypto_aead.h"
#include "romulus_m.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CRYPTO_BYTES 32
#define CRYPTO_NSECBYTES 0

int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k
)
{
    return romulus_m_decrypt(m, mlen, nsec, c, clen, ad, adlen, npub, k);
}

void string2hexString(char* input, int inputLen, char* output)
{
    for (int i = 0; i < inputLen; i++) {
        sprintf(output + (i * 2), "%02X", (unsigned char)input[i]);
    }
}

void hexToBytes(const char* hexString, unsigned char* byteArray, size_t byteArrayLen)
{
    for (size_t i = 0; i < byteArrayLen; i++) {
        sscanf(hexString + (i * 2), "%2hhx", &byteArray[i]);
    }
}

int decrypt()
{
    unsigned char m[CRYPTO_BYTES];  // Output buffer for the decrypted message
    unsigned long long mlen;

    unsigned char nsec[CRYPTO_NSECBYTES];  // Non-secret value buffer (can be set to NULL)

    char cipherHex[CRYPTO_BYTES * 2 + 1];
    printf("Enter the ciphertext in hexadecimal: ");
    scanf("%s", cipherHex);

    size_t clen = strlen(cipherHex) / 2;
    unsigned char* c = (unsigned char*)malloc(clen);
    hexToBytes(cipherHex, c, clen);  // Convert hexadecimal string to bytes

    const unsigned char* ad = NULL;  // No additional data
    unsigned long long adlen = 0;  // Length of the additional data

    const unsigned char* npub = (const unsigned char*)"000000000000111111111111";
    const unsigned char* k = (const unsigned char*)"0123456789ABCDEF0123456789ABCDEF";

    int result = crypto_aead_decrypt(m, &mlen, nsec, c, clen, ad, adlen, npub, k);

    if (result == 0) {
        printf("Decryption succeeded. Decrypted message: ");
        for (unsigned long long i = 0; i < mlen; i++) {
            printf("%c", m[i]);
        }
        printf("\n");
    } else {
        printf("Decryption failed.\n");
    }

    free(c);

    return 0;
}
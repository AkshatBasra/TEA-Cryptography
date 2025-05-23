// TEA Tiny Encryption Algorithm in "CBC mode" C Implementation by Sam Muldrow.
// 3-24-23
// UNH CS727
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

char *keyFileName = NULL;
char *plainTextFileName = NULL;
char *cipherTextFileName = NULL;
char *ivFileName = NULL;

FILE *keyFile = NULL;
FILE *plainTextFile = NULL;
FILE *cipherTextFile = NULL;
FILE *ivFile = NULL;

// TEA encode
// void encode(uint32_t v[2], const uint32_t k[4]) {
//     uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
//     uint32_t delta=0x9E3779B9;                     /* a key schedule constant */
//     uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
//     for (i=0; i<32; i++) {                         /* basic cycle start */
//         sum += delta;
//         v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
//         v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
//     }                                              /* end cycle */
//     v[0]=v0; v[1]=v1;
//     return;
// }


// bit_positions should have exactly 32 elements, values in 0–127
uint32_t extract_constant(const uint32_t k[4]) {
    uint32_t result = 0;

    int bit_positions[32];
    for (int i = 0; i < 32; ++i) {
        bit_positions[i] = i * 4;
    }

    for (int i = 0; i < 32; ++i) {
        int bit_pos = bit_positions[i];

        if (bit_pos < 0 || bit_pos > 127) {
            fprintf(stderr, "Invalid bit position: %d\n", bit_pos);
            return 0;
        }

        int word_index = bit_pos / 32;
        int bit_index  = 31 - (bit_pos % 32); // MSB-first bit order

        uint32_t bit = (k[word_index] >> bit_index) & 1;
        result = (result << 1) | bit;
    }

    return result;
}

void xtea_encode(uint32_t v[2], const uint32_t k[4], const uint32_t delta) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    // const uint32_t delta = 0x9E3779B9;
    for (uint32_t i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
    v[0] = v0; v[1] = v1;
}


int main(int argc, char** argv) {
    if (argc != 5) {
        printf("Usage: %s <IV file> <Key file> <Plaintext file> <Ciphertext file>\n", argv[0]);
        return -1;
    }

    ivFileName = argv[1];
    keyFileName = argv[2];
    plainTextFileName = argv[3];
    cipherTextFileName = argv[4];

    ivFile = fopen(ivFileName, "rb");
    keyFile = fopen(keyFileName, "rb");
    plainTextFile = fopen(plainTextFileName, "rb");
    cipherTextFile = fopen(cipherTextFileName, "wb");

    if (!ivFile || !keyFile || !plainTextFile || !cipherTextFile) {
        printf("Error opening one or more files.\n");
        return -1;
    }

    uint32_t *v = (uint32_t*)calloc(2, sizeof(uint32_t));
    uint32_t *v2 = (uint32_t*)calloc(2, sizeof(uint32_t));
    uint32_t *k = (uint32_t*)calloc(4, sizeof(uint32_t));
    fread(k, sizeof(uint32_t), 4, keyFile);
    fread(v2, sizeof(uint32_t), 2, ivFile);

    // Extract the constant from the key
    uint32_t delta = extract_constant(k);
    if (delta == 0) {
        printf("Error extracting constant from key.\n");
        free(v); free(v2); free(k);
        return -1;
    }
    printf("Extracted constant: %08X\n", delta);


    int blockNum = 0;
    while (1) {
        size_t bytesRead = fread(v, sizeof(uint32_t), 2, plainTextFile);
        if (bytesRead == 0) break;

        if (bytesRead < 2) {
            printf("Padding added to last block\n");
            uint8_t *vBytes = (uint8_t *)v;
            size_t totalBytes = bytesRead * sizeof(uint32_t);
            uint8_t padVal = 8 - totalBytes;
            for (size_t i = totalBytes; i < 8; i++) {
                vBytes[i] = padVal;
            }
        }

        v[0] ^= v2[0];
        v[1] ^= v2[1];
        xtea_encode(v, k, delta);
        fwrite(v, sizeof(uint32_t), 2, cipherTextFile);

        v2[0] = v[0];
        v2[1] = v[1];
        v[0] = 0;
        v[1] = 0;

        if (bytesRead < 2) break;
    }

    fclose(ivFile);
    fclose(keyFile);
    fclose(plainTextFile);
    fclose(cipherTextFile);
    free(v); free(v2); free(k);
    return 0;
}

/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * 
 * Notes : base implementation of ChaCha20
 */

#include "utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/**
 * Printing HEX data.
 */
static VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
  printf("unsigned char %s[] = {", Name);

  for (int i = 0; i < Size; i++) {
    if (i % 16 == 0)
      printf("\n\t");

    if (i < Size - 1) {
      printf("0x%0.2X, ", Data[i]);
    } else {
      printf("0x%0.2X ", Data[i]);
    }
  }

  printf("\n};\n\n\n");
}

/**
 * Notes : ChaCha must used payload % 64 == 0;
 */
static BOOL isValidPayload(SIZE_T sPayloadSize){
    return sPayloadSize % 64 == 0;
}

/**
 * Calculating padding needed.
 */
static SIZE_T paddingNeeded(SIZE_T sPayloadSize){
    return (64 - (sPayloadSize % 64));
}

/**
 * return ptr to padded payload.
 */
PBYTE allocatePadding(PBYTE pPayload, SIZE_T *sPayloadSize){
    if(isValidPayload(*sPayloadSize)){
        return pPayload;
    }
    else {
        SIZE_T paddingSize = paddingNeeded(*sPayloadSize);
        SIZE_T newSize = *sPayloadSize + paddingSize;

        PBYTE newPayload = realloc(pPayload, newSize);
        if(newPayload == NULL){
            return NULL;
        }

        memset(newPayload + *sPayloadSize, 0, paddingSize);
        *sPayloadSize = newSize;
        
        return newPayload;
    }
}

// ChaCha20 context
typedef struct {
    uint32_t state[16];
} ChaCha20Ctx;

static VOID ChaCha20Init(ChaCha20Ctx *ctx, const uint8_t *key, const uint8_t *nonce, uint32_t counter) {
    const char *constants = "expand 32-byte k";

    ctx->state[0] = ((uint32_t*)constants)[0];
    ctx->state[1] = ((uint32_t*)constants)[1];
    ctx->state[2] = ((uint32_t*)constants)[2];
    ctx->state[3] = ((uint32_t*)constants)[3];

    ctx->state[4] = ((uint32_t*)key)[0];
    ctx->state[5] = ((uint32_t*)key)[1];
    ctx->state[6] = ((uint32_t*)key)[2];
    ctx->state[7] = ((uint32_t*)key)[3];
    ctx->state[8] = ((uint32_t*)key)[4];
    ctx->state[9] = ((uint32_t*)key)[5];
    ctx->state[10] = ((uint32_t*)key)[6];
    ctx->state[11] = ((uint32_t*)key)[7];

    ctx->state[12] = counter;
    ctx->state[13] = ((uint32_t*)nonce)[0];
    ctx->state[14] = ((uint32_t*)nonce)[1];
    ctx->state[15] = ((uint32_t*)nonce)[2];
}

//Encryption.
static VOID ChaCha20Encrypt(ChaCha20Ctx *ctx, uint8_t *data, size_t len) {
    uint8_t block[64];
    size_t i, j;

    for (i = 0; i < len; i += 64) {
        uint32_t working_state[16];
        memcpy(working_state, ctx->state, sizeof(ctx->state));

        for (j = 0; j < 10; ++j) {
            #define QUARTERROUND(a, b, c, d) \
                working_state[a] += working_state[b]; working_state[d] ^= working_state[a]; working_state[d] = (working_state[d] << 16) | (working_state[d] >> (32 - 16)); \
                working_state[c] += working_state[d]; working_state[b] ^= working_state[c]; working_state[b] = (working_state[b] << 12) | (working_state[b] >> (32 - 12)); \
                working_state[a] += working_state[b]; working_state[d] ^= working_state[a]; working_state[d] = (working_state[d] << 8) | (working_state[d] >> (32 - 8)); \
                working_state[c] += working_state[d]; working_state[b] ^= working_state[c]; working_state[b] = (working_state[b] << 7) | (working_state[b] >> (32 - 7));

            QUARTERROUND(0, 4, 8, 12);
            QUARTERROUND(1, 5, 9, 13);
            QUARTERROUND(2, 6, 10, 14);
            QUARTERROUND(3, 7, 11, 15);
            QUARTERROUND(0, 5, 10, 15);
            QUARTERROUND(1, 6, 11, 12);
            QUARTERROUND(2, 7, 8, 13);
            QUARTERROUND(3, 4, 9, 14);
        }

        for (j = 0; j < 16; ++j) {
            ((uint32_t*)block)[j] = working_state[j] + ctx->state[j];
        }

        ctx->state[12]++;

        for (j = 0; j < 64 && i + j < len; ++j) {
            data[i + j] ^= block[j];
        }
    }
}

//test
int main() {
    unsigned char raw_payload_data[] = { 0x01, 0x02, 0x03, 0x04 }; // Exemple
    SIZE_T payloadSize = sizeof(raw_payload_data);

    PBYTE paddedPayload = malloc(payloadSize);
    if (paddedPayload == NULL) {
        printf("[!] Error allocating memory. \n");
        return EXIT_FAILURE;
    }

    memcpy(paddedPayload, raw_payload_data, payloadSize);

    // Payload with padding.
    paddedPayload = allocatePadding(paddedPayload, &payloadSize);
    if (paddedPayload == NULL) {
        printf("[!] An error occurred creating new padded payload. \n");
        return EXIT_FAILURE;
    }

    // Print padded payload.
    PrintHexData("Payload padded", paddedPayload, payloadSize);

    // ChaCha20 encryption
    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint32_t counter = 1;

    ChaCha20Ctx ctx;

    //Encrypt
    ChaCha20Init(&ctx, key, nonce, counter);
    ChaCha20Encrypt(&ctx, paddedPayload, payloadSize);
    PrintHexData("Encrypted payload", paddedPayload, payloadSize);

    //Decrypt
    ChaCha20Init(&ctx, key, nonce, counter);
    ChaCha20Encrypt(&ctx, paddedPayload, payloadSize);
    PrintHexData("Decrypted payload", paddedPayload, payloadSize);

    free(paddedPayload);
    return EXIT_SUCCESS;
}
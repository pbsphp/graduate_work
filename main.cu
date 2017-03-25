#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "des.h"
#include "aes.h"
#include "blowfish.h"
#include "gost.h"

#include "config.h"


void des_demo()
{
    uint64_t *data = NULL;
    cudaHostAlloc(
        (void **) &data, WORK_MEM_SIZE,
        cudaHostAllocWriteCombined | cudaHostAllocMapped
    );
    int len = WORK_MEM_SIZE / sizeof(uint64_t);

    const uint64_t key = 0xDEADFACEDEADFACE;

    for (int i = 0; i < len; ++i) {
        data[i] = 0x0DEFECA7EDCAFFEE;
    }

    printf("DES: %lx -> ", data[0]);
    des_encrypt(data, len, key);
    printf("%lx -> ", data[0]);
    des_decrypt(data, len, key);
    printf("%lx\n", data[0]);

    const uint64_t keys[3] = { 0x12345678ABCDEF00, 0xDEADFACEDEADFACE, 0xDEADBEEFDEADBEEF };

    printf("3DES: %lx -> ", data[0]);
    tdes_ede_encrypt(data, len, keys);
    printf("%lx -> ", data[0]);
    tdes_ede_decrypt(data, len, keys);
    printf("%lx\n", data[0]);

    cudaFreeHost(data);
}


void aes_demo()
{
    const uint8_t key[16] = {
        0x0f, 0x15, 0x71, 0xc9,
        0x47, 0xd9, 0xe8, 0x59,
        0x0c, 0xb7, 0xad, 0xd6,
        0xaf, 0x7f, 0x67, 0x98
    };

    uint8_t *data = NULL;
    cudaHostAlloc(
        (void **) &data, WORK_MEM_SIZE,
        cudaHostAllocWriteCombined | cudaHostAllocMapped
    );
    int len = WORK_MEM_SIZE / 16;

    for (int block_num = 0; block_num < len; ++block_num) {
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                data[block_num + i * 4 + j] = 0xC0;
            }
        }
    }

    printf("AES: ");
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            printf("%x ", data[i * 4 + j]);
        }
    }
    printf("-> ");

    aes_encrypt(data, len, key);

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            printf("%x ", data[i * 4 + j]);
        }
    }
    printf("-> ");

    aes_decrypt(data, len, key);

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            printf("%x ", data[i * 4 + j]);
        }
    }
    printf("\n");

    cudaFreeHost(data);
}


void blowfish_demo()
{
    const int key_size = 8;
    const uint8_t user_key[key_size] = {0xDE, 0xAD, 0xBE, 0xEF, 0xAB, 0xCD, 0xEF, 0x11};

    uint64_t *data = NULL;
    cudaHostAlloc(
        (void **) &data, WORK_MEM_SIZE,
        cudaHostAllocWriteCombined | cudaHostAllocMapped
    );
    int len = WORK_MEM_SIZE / sizeof(uint64_t);

    for (int i = 0; i < len; ++i) {
        data[i] = 0xDEFECA7ED000BEEF;
    }

    printf("Blowfish: %lx -> ", data[0]);
    blowfish_encrypt(data, len, user_key, key_size);
    printf("%lx -> ", data[0]);
    blowfish_decrypt(data, len, user_key, key_size);
    printf("%lx\n", data[0]);

    cudaFreeHost(data);
}


void gost_demo()
{
    const uint32_t key[8] = {
        0xDEADBEEF, 0xDEADC0FE, 0xDEFECA7E, 0xABCD1234,
        0xAABBCCDD, 0x01742319, 0xDADADEDE, 0xCACE1000
    };

    uint64_t *data = NULL;
    cudaHostAlloc(
        (void **) &data, WORK_MEM_SIZE,
        cudaHostAllocWriteCombined | cudaHostAllocMapped
    );
    int len = WORK_MEM_SIZE / sizeof(uint64_t);

    for (int i = 0; i < len; ++i) {
        data[i] = 0xDEFECA7ED000BEEF;
    }

    printf("GOST: %lx -> ", data[0]);
    gost_encrypt(data, len, key);
    printf("%lx -> ", data[0]);
    gost_decrypt(data, len, key);
    printf("%lx\n", data[0]);

    cudaFreeHost(data);
}


int main()
{
    des_demo();
    aes_demo();
    blowfish_demo();
    gost_demo();

    printf("%d\n", cudaGetLastError());

    return 0;
}

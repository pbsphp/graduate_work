#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "des.h"
#include "aes.h"
#include "blowfish.h"
#include "gost.h"


const int TOTAL_DATA = 1005000;


void des_demo()
{
    uint64_t *data = (uint64_t *) malloc(TOTAL_DATA * sizeof(uint64_t));

    const uint64_t key = 0xDEADFACEDEADFACE;

    for (int i = 0; i < TOTAL_DATA; ++i) {
        data[i] = 0x0DEFECA7EDCAFFEE;
    }

    for (int i = 0; i < 500; ++i) {
        des_encrypt(data, TOTAL_DATA, key);
        des_decrypt(data, TOTAL_DATA, key);
    }

    const uint64_t keys[3] = { 0x12345678ABCDEF00, 0xDEADFACEDEADFACE, 0xDEADBEEFDEADBEEF };

    for (int i = 0; i < 500; ++i) {
        tdes_ede_encrypt(data, TOTAL_DATA, keys);
        tdes_ede_decrypt(data, TOTAL_DATA, keys);
    }

    for (int i = 0; i < 5; ++i) {
        printf("%lx\n", data[i]);
    }

    free(data);
}


void aes_demo()
{
    uint8_t *data = (uint8_t *) malloc(TOTAL_DATA * 16);

    for (int block_num = 0; block_num < TOTAL_DATA; ++block_num) {
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                data[block_num + i * 4 + j] = 0xC0;
            }
        }
    }

    const uint8_t pizda[16] = {
        0x0f, 0x15, 0x71, 0xc9,
        0x47, 0xd9, 0xe8, 0x59,
        0x0c, 0xb7, 0xad, 0xd6,
        0xaf, 0x7f, 0x67, 0x98
    };

    aes_encrypt(data, TOTAL_DATA, pizda);

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            printf("%x ", data[i * 4 + j]);
        }
        printf("\n");
    }
    printf("\n");

    aes_decrypt(data, TOTAL_DATA, pizda);

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            printf("%x ", data[i * 4 + j]);
        }
        printf("\n");
    }
}


void blowfish_demo()
{
    const uint8_t user_key[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xAB, 0xCD, 0xEF, 0x11};

    uint64_t *data = (uint64_t *) malloc(sizeof(uint64_t) * TOTAL_DATA);
    for (int i = 0; i < TOTAL_DATA; ++i) {
        data[i] = 0xDEFECA7ED000BEEF;
    }

    blowfish_encrypt(data, TOTAL_DATA, user_key, 8);
    printf("%lx\n", data[0]);

    blowfish_decrypt(data, TOTAL_DATA, user_key, 8);
    printf("%lx\n", data[0]);

    free(data);
}


void gost_demo()
{
    const uint32_t key[8] = {
        0xDEADBEEF, 0xDEADC0FE, 0xDEFECA7E, 0xABCD1234,
        0xAABBCCDD, 0x01742319, 0xDADADEDE, 0xCACE1000
    };
    uint64_t *data = (uint64_t *) malloc(sizeof(uint64_t) * TOTAL_DATA);
    for (int i = 0; i < TOTAL_DATA; ++i) {
        data[i] = 0xDEFECA7ED000BEEF;
    }

    gost_encrypt(data, TOTAL_DATA, key);
    printf("%lx\n", data[0]);

    gost_decrypt(data, TOTAL_DATA, key);
    printf("%lx\n", data[0]);

    free(data);
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

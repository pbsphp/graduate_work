#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "des.h"


int main()
{
    const int TOTAL_DATA = 1005000;

    uint64_t *data = (uint64_t *) malloc(TOTAL_DATA * sizeof(uint64_t));

    for (int i = 0; i < TOTAL_DATA; ++i) {
        data[i] = 0xDEFECA7ED1C0FFEE;
    }

    // const uint64_t key = 0xDEADFACEDEADFACE;

    // for (int i = 0; i < 500; ++i) {
    //     des_encrypt(data, TOTAL_DATA, key);
    //     des_decrypt(data, TOTAL_DATA, key);
    // }

    const uint64_t keys[3] = { 0x12345678ABCDEF00, 0xDEADFACEDEADFACE, 0xDEADBEEFDEADBEEF };

    for (int i = 0; i < 500; ++i) {
        tdes_ede_encrypt(data, TOTAL_DATA, keys);
        tdes_ede_decrypt(data, TOTAL_DATA, keys);
    }

    for (int i = 0; i < 5; ++i) {
        printf("%lx\n", data[i]);
    }

    printf("%d\n", cudaGetLastError());

    free(data);

    return 0;
}

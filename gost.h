#include <stdint.h>

#ifndef GOST_H
#define GOST_H


/**
 * Выполняет шифрование по ГОСТ 28147-89
 * data - массив 64-битных данных для шифрования,
 * len - количество 64-битных блоков,
 * key - 256-битный ключ (массив 32-битных частей).
 */
void gost_encrypt(uint64_t *data, int len, const uint32_t *key);


/**
 * Выполняет расшифровку по ГОСТ 28147-89
 * cipher - массив 64-битных блоков шифротекста,
 * len - количество 64-битных блоков,
 * key - 256-битный ключ (массив 32-битных частей).
 */
void gost_decrypt(uint64_t *cipher, int len, const uint32_t *key);

#endif

#include <stdint.h>

#ifndef GOST_H
#define GOST_H


/**
 * Выполняет шифрование по ГОСТ 28147-89
 * data - массив 64-битных данных для шифрования,
 * len - количество 64-битных блоков,
 * key - 256-битный ключ (массив 32-битных частей).
 */
void gost_encrypt(void *data, size_t len, const void *key);


/**
 * Выполняет расшифровку по ГОСТ 28147-89
 * cipher - массив 64-битных блоков шифротекста,
 * len - количество 64-битных блоков,
 * key - 256-битный ключ (массив 32-битных частей).
 */
void gost_decrypt(void *cipher, size_t len, const void *key);

#endif

#include <stdint.h>

#ifndef DES_H
#define DES_H


/**
 * Выполняет шифрование блока данных.
 * data - массив 64-битных блоков данных,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ.
 */
void des_encrypt(uint64_t *data, size_t len, uint64_t key);


/**
 * Выполняет расшифровку блока данных.
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ,
 */
void des_decrypt(uint64_t *data, size_t len, uint64_t key);

#endif

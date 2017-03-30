#include <stdint.h>

#ifndef DES_H
#define DES_H


/**
 * Выполняет шифрование блока данных по алгоритму DES.
 * data - массив 64-битных блоков данных,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ.
 */
void des_encrypt(void *data, size_t len, const void *key);


/**
 * Выполняет расшифровку блока данных по алгоритму DES.
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ,
 */
void des_decrypt(void *data, size_t len, const void *key);


/**
 * Выполняет расшифровку блока данных по алгоритму 3DES(EDE).
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * keys - 3 64-битнх ключа,
 */
void tdes_ede_encrypt(void *data, size_t len, const void *keys);


/**
 * Выполняет расшифровку блока данных по алгоритму 3DES(EDE).
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * keys - 3 64-битнх ключа,
 */
void tdes_ede_decrypt(void *data, size_t len, const void *keys);

#endif

#include <stdint.h>

#ifndef AES_H
#define AES_H


/**
 * Выполняет шифрование данных по алгоритму AES.
 * data - массив данных (кратен 16 байтам, размеру одного блока),
 * len - количество блоков (4x4 байта),
 * key - ключ (128-бит, 16-байтный массив).
 */
void aes_encrypt(void *data, size_t len, const void *key);


/**
 * Выполняет расшифровку данных по алгоритму AES.
 * cipher - массив шифротекста (кратен 16 байтам, размеру одного блока),
 * len - количество блоков (4x4 байта),
 * key - ключ (128-бит, 16-байтный массив).
 */
void aes_decrypt(void *cipher, size_t len, const void *key);

#endif

#include <stdint.h>

#ifndef AES_H
#define AES_H


/**
 * Выполняет шифрование данных по алгоритму AES.
 * data - массив данных (кратен 16 байтам, размеру одного блока),
 * len - количество блоков (4x4 байта),
 * key - ключ (128-бит, 16-байтный массив).
 */
void aes_encrypt(uint8_t *data, int len, const uint8_t *key);


/**
 * Выполняет расшифровку данных по алгоритму AES.
 * cipher - массив шифротекста (кратен 16 байтам, размеру одного блока),
 * len - количество блоков (4x4 байта),
 * key - ключ (128-бит, 16-байтный массив).
 */
void aes_decrypt(uint8_t *cipher, int len, const uint8_t *key);

#endif

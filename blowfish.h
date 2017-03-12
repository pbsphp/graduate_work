#include <stdint.h>

#ifndef BLOWFISH_H
#define BLOWFISH_H

/**
 * Выполняет шифрование данных по алгоритму Blowfish.
 * data - массив исходных данных (64-битных),
 * len - длина исходных данных (количество 64-битных блоков),
 * user_key - пользовательский ключ,
 * key_len - длина ключа.
 */
void blowfish_encrypt(uint64_t *data, int len,
                      const uint8_t *user_key, int key_len);


/**
 * Выполняет дешифрование данных по алгоритму Blowfish.
 * cipher - массив шифротекста (64-битных блоков),
 * len - длина шифротекста (количество 64-битных блоков),
 * user_key - пользовательский ключ,
 * key_len - длина ключа.
 */
void blowfish_decrypt(uint64_t *cipher, int len,
                      const uint8_t *user_key, int key_len);

#endif

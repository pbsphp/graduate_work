#include <stdint.h>

#ifndef BLOWFISH_H
#define BLOWFISH_H

// Размер ключа может меняться
#define BLOWFISH_KEY_LEN 8


/**
 * Выполняет шифрование данных по алгоритму Blowfish.
 * data - массив исходных данных (64-битных),
 * len - длина исходных данных (количество 64-битных блоков),
 * user_key - пользовательский ключ.
 */
void blowfish_encrypt(void *data, size_t len, const void *user_key);


/**
 * Выполняет дешифрование данных по алгоритму Blowfish.
 * cipher - массив шифротекста (64-битных блоков),
 * len - длина шифротекста (количество 64-битных блоков),
 * user_key - пользовательский ключ.
 */
void blowfish_decrypt(void *cipher, size_t len, const void *user_key);

#endif

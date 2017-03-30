#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "des.h"
#include "aes.h"
#include "blowfish.h"
#include "gost.h"

#include "config.h"


#define ENCRYPTION 1
#define DECRYPTION 2


/**
 * Округляет число в большую сторону до кратности base.
 *
 * Например:
 * round_up_to_base(30, 8) = 32,
 * round_up_to_base(1234, 100) = 1300
 */
int round_up_to_base(int num, int base)
{
    return base * ((num + base - 1) / base);
}


/**
 * Возвращает размер файла
 */
long get_file_size(FILE *f)
{
    long curr_pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, curr_pos, SEEK_SET);
    return fsize;
}


/**
 * Шифрует файл.
 * function - указатель на функцию шифровки/расшифровки.
 * Функция должна принимать следующие аргументы:
 *   - массив данных,
 *   - количество блоков,
 *   - массив ключей (указатель на ключ, если он один).
 * in_fname - путь к входному файлу,
 * out_fname - путь к выходному файлу,
 * keys - массив ключей (будет передан функции function),
 * align - выравнивание (размер блока алгоритма в байтах).
 */
void encrypt_file(
    void (*function) (void *, size_t, const void *),
    const char *in_fname, const char *out_fname,
    void *keys, size_t align)
{
    unsigned char *buffer = NULL;
    cudaHostAlloc(
        (void **) &buffer, WORK_MEM_SIZE,
        cudaHostAllocWriteCombined | cudaHostAllocMapped
    );

    FILE *f_in = fopen(in_fname, "rb");
    FILE *f_out = fopen(out_fname, "wb");

    if (f_in == NULL || f_out == NULL) {
        printf("IO error!\n");
        exit(EXIT_FAILURE);
    }

    // Первые 8 байт зашифрованного файла - его длина (big endian).
    uint64_t file_size = (uint64_t) get_file_size(f_in);

    unsigned char file_size_be[8] = {0};
    for (int i = 0; i < 8; ++i) {
        file_size_be[7 - i] = file_size & 0xFF;
        file_size >>= 8;
    }

    fwrite(file_size_be, 1, 8, f_out);

    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, WORK_MEM_SIZE, f_in)) != 0) {

        // Передаваемая обработчику инфа должна быть кратной align.
        size_t aligned_size = round_up_to_base(bytes_read, align);

        // Остальное заполняем нулями
        for (size_t i = bytes_read; i < aligned_size; ++i) {
            buffer[i] = 0;
        }

        function((void *) buffer, aligned_size / align, keys);
        fwrite(buffer, 1, aligned_size, f_out);
    }

    fclose(f_in);
    fclose(f_out);

    cudaFreeHost(buffer);
}


/**
 * Дешифрует файл.
 * function - указатель на функцию шифровки/расшифровки.
 * Функция должна принимать следующие аргументы:
 *   - массив данных,
 *   - количество блоков,
 *   - массив ключей (указатель на ключ, если он один).
 * in_fname - путь к входному файлу,
 * out_fname - путь к выходному файлу,
 * keys - массив ключей (будет передан функции function),
 * align - выравнивание (размер блока алгоритма в байтах).
 */
void decrypt_file(
    void (*function) (void *, size_t, const void *),
    const char *in_fname, const char *out_fname,
    void *keys, size_t align)
{
    unsigned char *buffer = NULL;
    cudaHostAlloc(
        (void **) &buffer, WORK_MEM_SIZE,
        cudaHostAllocWriteCombined | cudaHostAllocMapped
    );

    FILE *f_in = fopen(in_fname, "rb");
    FILE *f_out = fopen(out_fname, "wb");

    if (f_in == NULL || f_out == NULL) {
        printf("IO error!\n");
        exit(EXIT_FAILURE);
    }

    // Первые 8 байт зашифрованного файла - его длина (big endian).
    unsigned char file_size_be[8] = {0};
    fread(file_size_be, 1, 8, f_in);
    uint64_t expected_write = 0;
    for (int i = 0; i < 8; ++i) {
        expected_write <<= 8;
        expected_write |= file_size_be[i];
    }

    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, WORK_MEM_SIZE, f_in)) != 0) {

        // Передаваемая обработчику инфа должна быть кратной align.
        size_t aligned_size = round_up_to_base(bytes_read, align);

        // Остальное заполняем нулями
        for (size_t i = bytes_read; i < aligned_size; ++i) {
            buffer[i] = 0;
        }

        size_t write_bytes = (
            (bytes_read < expected_write) ? bytes_read : expected_write);

        function((void *) buffer, aligned_size / align, keys);
        fwrite(buffer, 1, write_bytes, f_out);

        expected_write -= bytes_read;
    }

    fclose(f_in);
    fclose(f_out);

    cudaFreeHost(buffer);
}


int main()
{
    const uint32_t gost_key[8] = {
        0xDEADBEEF, 0xDEADC0FE, 0xDEFECA7E, 0xABCD1234,
        0xAABBCCDD, 0x01742319, 0xDADADEDE, 0xCACE1000
    };

    const uint64_t des_key = 0xDEADFACEDEADFACE;

    const uint64_t tdes_keys[3] = {
        0x12345678ABCDEF00, 0xDEADFACEDEADFACE, 0xDEADBEEFDEADBEEF
    };

    const uint8_t aes_key[16] = {
        0x0f, 0x15, 0x71, 0xc9,
        0x47, 0xd9, 0xe8, 0x59,
        0x0c, 0xb7, 0xad, 0xd6,
        0xaf, 0x7f, 0x67, 0x98
    };

    const uint8_t blowfish_key[] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xAB, 0xCD, 0xEF, 0x11
    };

    encrypt_file(
        des_encrypt,
        "/tmp/in.txt", "/tmp/.cipher",
        (void *) &des_key,
        sizeof(uint64_t)
    );

    decrypt_file(
        des_decrypt,
        "/tmp/.cipher", "/tmp/des.txt",
        (void *) &des_key,
        sizeof(uint64_t)
    );

    encrypt_file(
        tdes_ede_encrypt,
        "/tmp/in.txt", "/tmp/.cipher",
        (void *) tdes_keys,
        sizeof(uint64_t)
    );

    decrypt_file(
        tdes_ede_decrypt,
        "/tmp/.cipher", "/tmp/tdes.txt",
        (void *) tdes_keys,
        sizeof(uint64_t)
    );

    encrypt_file(
        aes_encrypt,
        "/tmp/in.txt", "/tmp/out.txt",
        (void *) aes_key,
        16
    );

    decrypt_file(
        aes_decrypt,
        "/tmp/out.txt", "/tmp/aes.txt",
        (void *) aes_key,
        16
    );

    encrypt_file(
        blowfish_encrypt,
        "/tmp/in.txt", "/tmp/.cipher",
        (void *) blowfish_key,
        sizeof(uint64_t)
    );

    decrypt_file(
        blowfish_decrypt,
        "/tmp/.cipher", "/tmp/blowfish.txt",
        (void *) blowfish_key,
        sizeof(uint64_t)
    );

    encrypt_file(
        gost_encrypt,
        "/tmp/in.txt", "/tmp/.cipher",
        (void *) gost_key,
        sizeof(uint64_t)
    );

    decrypt_file(
        gost_decrypt,
        "/tmp/.cipher", "/tmp/gost.txt",
        (void *) gost_key,
        sizeof(uint64_t)
    );

    printf("%d\n", cudaGetLastError());

    return 0;
}

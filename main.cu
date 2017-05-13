#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "des.h"
#include "aes.h"
#include "blowfish.h"
#include "gost.h"

#include "config.h"
#include "helpers.h"


#define ENCRYPTION 1
#define DECRYPTION 2

#define ALG_DES 1
#define ALG_TDES 2
#define ALG_AES 3
#define ALG_BLOWFISH 4
#define ALG_GOST 5


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
    GPU_CHECK_ERROR(
        cudaHostAlloc(
            (void **) &buffer, WORK_MEM_SIZE,
            cudaHostAllocWriteCombined | cudaHostAllocMapped
        )
    );

    FILE *f_in = fopen(in_fname, "rb");
    FILE *f_out = fopen(out_fname, "wb");
    if (f_in == NULL) {
        printf("%s: No such file!\n", in_fname);
        exit(EXIT_FAILURE);
    }
    if (f_out == NULL) {
        printf("%s: Cannot open output file!\n", out_fname);
        exit(EXIT_FAILURE);
    }

    // Флаг того, что файл был дополнен.
    bool has_padding = false;

    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, WORK_MEM_SIZE, f_in)) != 0) {
        // Передаваемая обработчику инфа должна быть кратной align.
        size_t aligned_size = round_up_to_base(bytes_read, align);

        // Дополняем padding'ом (PKCS7)
        if (bytes_read < aligned_size) {
            for (size_t i = bytes_read; i < aligned_size; ++i) {
                buffer[i] = aligned_size - bytes_read;
            }
            has_padding = true;
        }

        function((void *) buffer, aligned_size / align, keys);
        fwrite(buffer, 1, aligned_size, f_out);
    }

    // Если в процессе обработки не было добавлено дополнение
    // (например размер файла кратен блоку или даже WORK_MEM_SIZE)
    // все равно его добавляем.
    if (!has_padding) {
        for (size_t i = 0; i < align; ++i) {
            buffer[i] = align;
        }

        function((void *) buffer, align / align, keys);
        fwrite(buffer, 1, align, f_out);
    }

    fclose(f_in);
    fclose(f_out);

    GPU_CHECK_ERROR(
        cudaFreeHost(buffer)
    );
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
    GPU_CHECK_ERROR(
        cudaHostAlloc(
            (void **) &buffer, WORK_MEM_SIZE,
            cudaHostAllocWriteCombined | cudaHostAllocMapped
        )
    );

    FILE *f_in = fopen(in_fname, "rb");
    FILE *f_out = fopen(out_fname, "wb");
    if (f_in == NULL) {
        printf("%s: No such file!\n", in_fname);
        exit(EXIT_FAILURE);
    }
    if (f_out == NULL) {
        printf("%s: Cannot open output file!\n", out_fname);
        exit(EXIT_FAILURE);
    }

    size_t expected_read = get_file_size(f_in);

    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, WORK_MEM_SIZE, f_in)) != 0) {
        expected_read -= bytes_read;

        // Передаваемая обработчику инфа должна быть кратной рамеру блока.
        if (bytes_read != round_up_to_base(bytes_read, align)) {
            printf(
                "Ciphertext is corrupted! File size does not match to block size (%ld bytes).\n",
                align
            );
            exit(1);
        }

        function((void *) buffer, bytes_read / align, keys);

        // Если был прочитан последний блок, необходимо убрать из него padding.
        size_t real_part_size = bytes_read;
        if (expected_read <= 0) {
            int padding = buffer[bytes_read - 1];
            real_part_size = bytes_read - padding;
        }

        fwrite(buffer, 1, real_part_size, f_out);
    }

    fclose(f_in);
    fclose(f_out);

    GPU_CHECK_ERROR(
        cudaFreeHost(buffer)
    );
}


/**
 * Считывает ключ из файла
 * fname - путь к файлу,
 * buffer - буфер для ключа,
 * length - предполагаемая длина ключа.
 */
void read_key_file(const char *fname, char *buffer, int length)
{
    FILE *key_file = fopen(fname, "rb");
    if (key_file == NULL) {
        printf("%s: no such file!\n", fname);
        exit(1);
    }

    int bytes_read = fread(buffer, 1, length, key_file);
    fclose(key_file);
    if (bytes_read != length) {
        printf(
            "Invalid key file. Expected %d bytes, got %d.\n",
            length, bytes_read
        );
        exit(1);
    }
}


int main(int argc, char *argv[])
{
    if (argc != 6) {
        printf(
            "Usage: %s <d|e> <des|tdes|aes|blowfish|gost> <keyfile> <in> <out>\n",
            argv[0]
        );
        exit(1);
    }

    int algorithm = 0;
    if (strcmp(argv[2], "des") == 0) {
        algorithm = ALG_DES;
    } else if (strcmp(argv[2], "tdes") == 0) {
        algorithm = ALG_TDES;
    } else if (strcmp(argv[2], "aes") == 0) {
        algorithm = ALG_AES;
    } else if (strcmp(argv[2], "blowfish") == 0) {
        algorithm = ALG_BLOWFISH;
    } else if (strcmp(argv[2], "gost") == 0) {
        algorithm = ALG_GOST;
    } else {
        printf("Invalid `alg' option. Not supported\n");
        exit(1);
    }

    int key_len = 0;
    switch (algorithm) {
    case ALG_DES:
        key_len = 8;
        break;
    case ALG_TDES:
        key_len = 3 * 8;
        break;
    case ALG_AES:
        key_len = 16;
        break;
    case ALG_BLOWFISH:
        key_len = 8;
        break;
    case ALG_GOST:
        key_len = 4 * 8;
        break;
    default:
        printf(
            "Internal error! Key length for this algorithm is not defined!\n"
        );
        exit(1);
    }

    char key_buffer[100];
    read_key_file(argv[3], key_buffer, key_len);

    const char *in_file = argv[4];
    const char *out_file = argv[5];

    if (strcmp(argv[1], "e") == 0) {
        switch (algorithm) {
        case ALG_DES:
            encrypt_file(
                des_encrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        case ALG_TDES:
            encrypt_file(
                tdes_ede_encrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        case ALG_AES:
            encrypt_file(
                aes_encrypt,
                in_file, out_file,
                (void *) key_buffer,
                16
            );
            break;
        case ALG_BLOWFISH:
            encrypt_file(
                blowfish_encrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        case ALG_GOST:
            encrypt_file(
                gost_encrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        }
    } else if (strcmp(argv[1], "d") == 0) {
        switch (algorithm) {
        case ALG_DES:
            decrypt_file(
                des_decrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        case ALG_TDES:
            decrypt_file(
                tdes_ede_decrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        case ALG_AES:
            decrypt_file(
                aes_decrypt,
                in_file, out_file,
                (void *) key_buffer,
                16
            );
            break;
        case ALG_BLOWFISH:
            decrypt_file(
                blowfish_decrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        case ALG_GOST:
            decrypt_file(
                gost_decrypt,
                in_file, out_file,
                (void *) key_buffer,
                sizeof(uint64_t)
            );
            break;
        }
    } else {
        printf("Encrypt or decrypt? See usage.\n");
        exit(1);
    }

    return 0;
}

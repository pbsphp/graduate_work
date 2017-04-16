#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "helpers.h"


#define STATE_SIZE 4
#define TOTAL_ROUNDS 10

#define RIGHT 1
#define LEFT 2

#define ENCRYPTION 1
#define DECRYPTION 2


// Таблицы трансформации для SubBytes, прямая и обратная.
#ifdef __CUDA_ARCH__
__device__
#endif
static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

__device__
static const uint8_t RSBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


// Используется при генерации ключей раундов (KeyExpansion)
static const uint8_t RCON[TOTAL_ROUNDS] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


// Множители при операции MixColumns.
// Данная матрица может быть вычислена, однако для
// ясности задана в виде константы.
__device__
static const int MIX_COLUMNS_MULTIPLIERS[STATE_SIZE][STATE_SIZE] = {
    {2, 3, 1, 1},
    {1, 2, 3, 1},
    {1, 1, 2, 3},
    {3, 1, 1, 2}
};

// При обратном преобразовании (RevMixColumns)
__device__
static const int REV_MIX_COLUMNS_MULTIPLIERS[STATE_SIZE][STATE_SIZE] = {
    {14, 11, 13,  9},
    { 9, 14, 11, 13},
    {13,  9, 14, 11},
    {11, 13,  9, 14}
};


/**
 * Заменяет байты в матрице согласно S-боксу.
 * В терминах AES - SubBytes.
 */
__device__
static inline void sub_bytes(uint8_t state[STATE_SIZE][STATE_SIZE],
                      const uint8_t *sbox)
{
    for (int i = 0; i < STATE_SIZE; ++i) {
        for (int j = 0; j < STATE_SIZE; ++j) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}


/**
 * Сдвигает строки матрицы влево или вправо.
 * 0 строку на 0 байт, 1 - на один, 2 - на 2, 3 - на 3.
 * В терминах AES - ShiftRows.
 */
__device__
static inline void shift_rows(uint8_t state[STATE_SIZE][STATE_SIZE],
                              int direction)
{
    uint8_t tmp[STATE_SIZE];
    for (int row = 1; row < STATE_SIZE; ++row) {
        for (int i = 0; i < STATE_SIZE; ++i) {
            if (direction == LEFT) {
                tmp[i] = state[row][(i + row) % STATE_SIZE];
            } else if (direction == RIGHT) {
                tmp[(i + row) % STATE_SIZE] = state[row][i];
            }
        }

        for (int i = 0; i < STATE_SIZE; ++i) {
            state[row][i] = tmp[i];
        }
    }
}


/**
 * Умножение в поле Галуа
 */
__device__
static inline uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    while (b) {
        if (b & 1) {
            p ^= a;
        }

        if (a & 0x80) {
            a = (a << 1) ^ 0x11b;
        } else {
            a *= 2;
        }
        b /= 2;
    }
    return p;
}


/**
 * Умножает столбец матрицы state на строку из MIX_COLUMNS_MULTIPLIERS.
 * Результат помещает в new_column.
 */
__device__
static inline void multiply_column(
    uint8_t *new_column, const uint8_t *column_copy, int encr_or_decr)
{
    for (int row = 0; row < STATE_SIZE; ++row) {
        uint8_t sum = 0;
        for (int pos = 0; pos < STATE_SIZE; ++pos) {
            uint8_t a = column_copy[pos];
            uint8_t b;
            if (encr_or_decr == ENCRYPTION) {
                b = MIX_COLUMNS_MULTIPLIERS[row][pos];
            } else if (encr_or_decr == DECRYPTION) {
                b = REV_MIX_COLUMNS_MULTIPLIERS[row][pos];
            }
            sum ^= gmul(a, b);
        }
        new_column[row] = sum;
    }
}


/**
 * Выполняет преобразование столбцов матрицы, умножая каждый
 * столбец на матрицу коэффициентов.
 * В терминах AES - MixColumns
 */
__device__
static void mix_columns(uint8_t state[STATE_SIZE][STATE_SIZE],
                        int encr_or_decr)
{
    for (int col = 0; col < STATE_SIZE; ++col) {
        uint8_t column_copy[STATE_SIZE] = {0};
        uint8_t new_column[STATE_SIZE] = {0};

        // Копируем столбец матрицы в отдельный массив и выполняем
        // его умножение на матрицу с коэффициентами.
        // Это неэффективно, зато очевидно.

        for (int i = 0; i < STATE_SIZE; ++i) {
            column_copy[i] = state[i][col];
        }

        multiply_column(new_column, column_copy, encr_or_decr);

        for (int i = 0; i < STATE_SIZE; ++i) {
            state[i][col] = new_column[i];
        }
    }
}


/**
 * XOR'ит все элементы двух матриц между собой.
 * Результат помещает в first.
 */
__device__
static inline void add_round_key(
    uint8_t first[STATE_SIZE][STATE_SIZE],
    uint8_t second[STATE_SIZE][STATE_SIZE])
{
    for (int i = 0; i < STATE_SIZE; ++i) {
        for (int j = 0; j < STATE_SIZE; ++j) {
            first[i][j] ^= second[i][j];
        }
    }
}


/**
 * Вращает (сдвигает) массив на один байт влево.
 */
static inline void key_rot_word_left(uint8_t *word)
{
    uint8_t tmp = word[0];
    for (int i = 0; i < STATE_SIZE - 1; ++i) {
        word[i] = word[i + 1];
    }
    word[STATE_SIZE - 1] = tmp;
}


/**
 * Генерирует очередной ключ раунда (расширяет ключ).
 * В терминологии AES - KeyExpansion.
 * key - матрица для результата (нового ключа раунда),
 * prev_key - ключ предыдущего раунда,
 * round_num - номер раунда.
 *
 * Расширение ключа выполняется следующим образом:
 * - Берется последний (четвертый) столбец предыдущего ключа,
 * - Над ним выполняются:
 *   - RotWord
 *   - SubBytes,
 *   - XOR с первым столбцом предыдущего ключа,
 *   - XOR первого байта с элементов вектора RCON (номер элемента
 *     соответствует текущему раунду).
 * - Следующие три столбца получаются XORом между соответствующим
 *   столбцом в предыдущем ключе и предыдущим столбцом в новом.
 */
static void key_expansion(uint8_t key[STATE_SIZE][STATE_SIZE],
                          uint8_t prev_key[STATE_SIZE][STATE_SIZE],
                          int round_num)
{
    uint8_t first_col[STATE_SIZE] = {0};
    for (int i = 0; i < STATE_SIZE; ++i) {
        first_col[i] = prev_key[i][STATE_SIZE - 1];
    }
    key_rot_word_left(first_col);

    for (int i = 0; i < STATE_SIZE; ++i) {
        first_col[i] = SBOX[first_col[i]];
    }

    for (int i = 0; i < STATE_SIZE; ++i) {
        first_col[i] ^= prev_key[i][0];
    }

    first_col[0] ^= RCON[round_num];

    for (int i = 0; i < STATE_SIZE; ++i) {
        key[i][0] = first_col[i];
    }

    for (int col = 1; col < STATE_SIZE; ++col) {
        for (int i = 0; i < STATE_SIZE; ++i) {
            key[i][col] = key[i][col - 1] ^ prev_key[i][col];
        }
    }
}


/**
 * Генерирует ключи раундов.
 * aes_key - байты ключа, 128-бит,
 * round_keys - массив[11/4/4], в который будут помещены ключи
 */
static void gen_round_keys(
    const uint8_t *aes_key,
    uint8_t round_keys[TOTAL_ROUNDS + 1][STATE_SIZE][STATE_SIZE])
{
    // Первый ключ просто вытаскиваем из aes_key.
    for (int i = 0; i < STATE_SIZE; ++i) {
        for (int j = 0; j < STATE_SIZE; ++j) {
            round_keys[0][j][i] = aes_key[i * STATE_SIZE + j];
        }
    }

    // Остальные ключи генерируются методом KeyExpansion
    for (int round_num = 0; round_num < TOTAL_ROUNDS; ++round_num) {
        key_expansion(
            round_keys[round_num + 1], round_keys[round_num], round_num);
    }
}


/**
 * Выполняет шифрование одного блока данных.
 * state - матрица с данными для шифрования. В ней же и будет размещен
 * результат.
 * round_keys - массив матриц ключей (для каждого раунда свой ключ).
 *
 * Шифрование выполняется следующим образом:
 * - К данным применяется AddRoundKey с начальным ключом.
 * - 9 раундов с операциями SubBytes, ShiftRows, MixColumns, AddRoundKey.
 * - 10 раунд, в котором не выполняется MixColumns.
 */
__device__
static void aes_encrypt_block(
    uint8_t state[STATE_SIZE][STATE_SIZE],
    uint8_t round_keys[TOTAL_ROUNDS + 1][STATE_SIZE][STATE_SIZE])
{
    add_round_key(state, round_keys[0]);

    for (int round_num = 0; round_num < TOTAL_ROUNDS - 1; ++round_num) {
        sub_bytes(state, SBOX);
        shift_rows(state, LEFT);
        mix_columns(state, ENCRYPTION);
        add_round_key(state, round_keys[round_num + 1]);
    }

    sub_bytes(state, SBOX);
    shift_rows(state, LEFT);
    add_round_key(state, round_keys[TOTAL_ROUNDS]);
}


/**
 * Выполняет расшифрование одного блока данных.
 * state - матрица с шифротекстом. В ней же и будет размещен
 * результат.
 * round_keys - массив матриц ключей (для каждого раунда свой ключ).
 *
 * Расшифровка выполняется способом обратным шифрованию,
 * см. aes_encrypt_block().
 */
__device__
static void aes_decrypt_block(
    uint8_t state[STATE_SIZE][STATE_SIZE],
    uint8_t round_keys[TOTAL_ROUNDS + 1][STATE_SIZE][STATE_SIZE])
{
    add_round_key(state, round_keys[TOTAL_ROUNDS]);
    shift_rows(state, RIGHT);
    sub_bytes(state, RSBOX);

    for (int round_num = TOTAL_ROUNDS - 2; round_num >= 0; --round_num) {
        add_round_key(state, round_keys[round_num + 1]);
        mix_columns(state, DECRYPTION);
        shift_rows(state, RIGHT);
        sub_bytes(state, RSBOX);
    }

    add_round_key(state, round_keys[0]);
}


/**
 * Выполняет шифрование или расшифровку массива данных.
 * all_data - массив данных,
 * len - количество блоков,
 * encr_or_decr - шифрование или расшифровка.
 */
__global__
static void map_aes(
    uint8_t *all_data, int len,
    uint8_t round_keys[TOTAL_ROUNDS + 1][STATE_SIZE][STATE_SIZE],
    int encr_or_decr, int device_loops)
{
    for (int iteration = 0; iteration < device_loops; ++iteration) {
        int worker_idx = blockIdx.x * THREADS_PER_BLOCK + threadIdx.x;
        int offset = THREADS_PER_BLOCK * BLOCKS_PER_GRID * iteration;
        int idx = offset + worker_idx;
        if (idx < len) {
            int bytes_offset = idx * STATE_SIZE * STATE_SIZE;

            // TODO: не копировать данные, попробовать привести к массиву.
            uint8_t state[STATE_SIZE][STATE_SIZE] = {0};
            for (int i = 0; i < STATE_SIZE; ++i) {
                for (int j = 0; j < STATE_SIZE; ++j) {
                    state[i][j] = all_data[bytes_offset + i * STATE_SIZE + j];
                }
            }

            if (encr_or_decr == ENCRYPTION) {
                aes_encrypt_block(state, round_keys);
            } else if (encr_or_decr == DECRYPTION) {
                aes_decrypt_block(state, round_keys);
            }

            for (int i = 0; i < STATE_SIZE; ++i) {
                for (int j = 0; j < STATE_SIZE; ++j) {
                    all_data[bytes_offset + i * STATE_SIZE + j] = state[i][j];
                }
            }
        }
    }
}


/**
 * Запускает процесс шифрования на GPU.
 * data - массив данных для обработки,
 * len - количество данных (блоков 4x4),
 * round_keys - раундовые ключи,
 * encr_or_decr - шифрование или расшифровка.
 * Запускает процесс вычисления, аллоцирует и освобождает память и т.д.
 */
static void aes_run_device(
    uint8_t *data, size_t len,
    uint8_t round_keys[TOTAL_ROUNDS + 1][STATE_SIZE][STATE_SIZE],
    int encr_or_decr)
{
    uint8_t *data_dev = NULL;
    GPU_CHECK_ERROR(
        cudaHostGetDevicePointer(&data_dev, data, 0)
    );

    uint8_t ***round_keys_dev = NULL;
    GPU_CHECK_ERROR(
        cudaMalloc((void **) &round_keys_dev, sizeof(round_keys_dev))
    );
    GPU_CHECK_ERROR(
        cudaMemcpy(
            round_keys_dev, round_keys,
            sizeof(round_keys_dev),
            cudaMemcpyHostToDevice
        )
    );

    // Запускаем обработку на девайсе
    int grid_size = THREADS_PER_BLOCK * BLOCKS_PER_GRID;
    int device_loops = (len + grid_size - 1) / grid_size;

    map_aes<<<BLOCKS_PER_GRID, THREADS_PER_BLOCK>>>(
        data_dev, len, (uint8_t (*)[4][4]) round_keys_dev, encr_or_decr,
        device_loops
    );
    GPU_CHECK_ERROR_STATE();

    GPU_CHECK_ERROR(
        cudaFree(round_keys_dev)
    );
    GPU_CHECK_ERROR(
        cudaThreadSynchronize()
    );
}


/**
 * Выполняет шифрование данных по алгоритму AES.
 * data - массив данных (кратен 16 байтам, размеру одного блока),
 * len - количество блоков (4x4 байта),
 * key - ключ (128-бит, 16-байтный массив).
 */
void aes_encrypt(void *data, size_t len, const void *key)
{
    uint8_t round_keys[TOTAL_ROUNDS + 1][STATE_SIZE][STATE_SIZE];
    gen_round_keys((const uint8_t *) key, round_keys);
    aes_run_device((uint8_t *) data, len, round_keys, ENCRYPTION);
}


/**
 * Выполняет расшифровку данных по алгоритму AES.
 * cipher - массив шифротекста (кратен 16 байтам, размеру одного блока),
 * len - количество блоков (4x4 байта),
 * key - ключ (128-бит, 16-байтный массив).
 */
void aes_decrypt(void *cipher, size_t len, const void *key)
{
    uint8_t round_keys[TOTAL_ROUNDS + 1][STATE_SIZE][STATE_SIZE];
    gen_round_keys((const uint8_t *) key, round_keys);
    aes_run_device((uint8_t *) cipher, len, round_keys, DECRYPTION);
}

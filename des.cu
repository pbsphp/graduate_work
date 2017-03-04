#include <stdbool.h>
#include <stdint.h>


#define THREADS_PER_BLOCK 500
#define BLOCKS_PER_ITERATION 1000
#define DATA_PER_ITERATION (THREADS_PER_BLOCK * BLOCKS_PER_ITERATION)


#define ENCRYPTION 1
#define DECRYPTION 2

#define STRATEGY_SIMPLE_DES 1
#define STRATEGY_3DES_EDE 2


// У DES 16 раундов
#define TOTAL_ROUNDS 16


// Начальная и конечная перестановки
__device__
static const int IP1[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};


__device__
static const int IP2[] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};


// P-бокс расширения
__device__
static const int P_BOX[] = {
    32,  1,  2,  3,  4,  5,  4,  5,
     6,  7,  8,  9,  8,  9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32,  1,
};


// Прямой P-бокс для раунда
__device__
static const int ROUND_P_BOX[] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3, 9,
    19, 13, 30,  6, 22, 11,  4, 25
};


// S-бокс
__device__
static const uint8_t S_BOX[8][4][TOTAL_ROUNDS] = {
   {
       {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
       { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
       { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
       {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
   }, {
       {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
       { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
       { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
       {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
   }, {
       {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
       {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
       {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
       { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
   }, {
       { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
       {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
       {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
       { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
   }, {
       { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
       {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
       { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
       {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
   }, {
       {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
       {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
       { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
       { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
   }, {
       { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
       {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
       { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
       { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
   }, {
       {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
       { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
       { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
       { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
   },
};


// Преобразования ключа из 64 бит в 56
static const int KEY_INIT_TRANSFORMS[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};


// Конечные преобразования раундового ключа из 56-битного в 48-битный
static const int KEY_FINAL_TRANSFORMS[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};


/**
 * Возвращает n бит из слова number.
 * number - число,
 * n - номер бита (слева, начиная с 0)
 * total_bits - сколько всего бит в числе (например 48).
 */
__host__ __device__
static inline unsigned get_bit(uint64_t number, int n, int total_bits)
{
    int n_left = total_bits - n - 1;
    return (number >> n_left) & 1;
}


/**
 * Циклически сдвигает биты числа влево.
 * number - число,
 * n - на сколько бит влево сдвинуть число,
 * total_bits - количество бит в числе.
 *
 * Пример:
 * number = 01110011, n = 2, total_bits = 8
 * number = 11001101.
 */
static inline uint64_t rotate_left(uint64_t number, int n, int total_bits)
{
    uint64_t rotated = (number << n) | (number >> (total_bits - n));
    uint64_t mask = (1 << total_bits) - 1;
    return rotated & mask;
}


/**
 * Выполняет начальную или конечную перестановку битов
 * по соответствующим таблицам, описаным в спецификации DES.
 * data - данные для перестановки (64 бита),
 * initial - начальная или конечная перестановка.
 */
__device__
static uint64_t apply_permutation(uint64_t data, bool initial)
{
    const int *ip = initial ? IP1 : IP2;

    uint64_t result = 0;
    for (int i = 0; i < 64; ++i) {
        result <<= 1;
        result |= get_bit(data, ip[i] - 1, 64);
    }
    return result;
}


/**
 * Выполняет P-бокс расширение данных с 32 до 48 бит.
 * data - начальные данные (32 бита).
 * Для расширения используется таблица P-box, описаная в спецификации DES.
 * Возвращает 48-битное (расширенное) число.
 */
__device__
static uint64_t pbox_transform(uint64_t data)
{
    uint64_t result = 0;
    for (int i = 0; i < 48; ++i) {
        result <<= 1;
        result |= get_bit(data, P_BOX[i] - 1, 32);
    }
    return result;
}


/**
 * Выполняет P-бокс преобразование в раундовой функции des.
 * Для преобразования данных использует прямо P-box раунда,
 * описаный в спецификации DES.
 */
__device__
static uint64_t round_pbox_transform(uint64_t data)
{
    uint64_t result = 0;
    for (int i = 0; i < 32; ++i) {
        result <<= 1;
        result |= get_bit(data, ROUND_P_BOX[i] - 1, 32);
    }
    return result;
}


/**
 * Выполняет S-бокс преобразование.
 * data - данные для преобразования (6-битное число),
 * vec_num - номер вектора преобразования (0-7, по количеству S-боксов).
 * Перестановка выполняется следующим образом:
 * 1 и 6 биты входного числа - номер строки, 2-5 - номер столбца.
 * По номеру строки и столбца в S-боксе ищется конечное число.
 * S-box задан в спецификации DES.
 */
__device__
static uint64_t sbox_transform(uint8_t data, int vec_num)
{
    int row = ((data >> 4) & 2) | (data & 1);
    int col = (data >> 1) & 0xF;
    return S_BOX[vec_num][row][col];
}


/**
 * Функция Фейстеля - шифрует 32 бита информации внутри раунда.
 * Данная функция вызывается в каждом раунде Фейстеля.
 * data - данные для шифрования,
 * subkey - подключ для данного раунда.
 *
 * Функция выполняет следующие этапы:
 * - Начальные 32-битные данные расширяются до 64-битных.
 * - Выполняется XOR с ключом.
 * - 48-битные данные делятся на 8 векторов, по 6 бит каждый.
 * - Над каждым вектором выполняется S-box преобразование,
 *   после чего получается 8 4-битных векторов.
 * - 8 4-битных векторов склеиваются в 32-битный.
 * - Выполняется прямое P-box преобразование.
 */
__device__
static uint64_t feistel_function(uint64_t data, uint64_t subkey)
{
    const int SIX_BITS = 0x3F;

    uint64_t result = pbox_transform(data);

    result ^= subkey;

    uint8_t vectors[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 7; i >= 0; --i) {
        vectors[i] = result & SIX_BITS;
        result >>= 6;
    }

    for (int i = 0; i < 8; ++i) {
        vectors[i] = sbox_transform(vectors[i], i);
    }

    result = 0;
    for (int i = 0; i < 8; ++i) {
        result <<= 4;
        result |= vectors[i];
    }

    result = round_pbox_transform(result);

    return result;
}


/**
 * Генерирует очередной ключ раунда Фейстеля.
 * Получает 28-битные векторы C0 и D0.
 * - Вектора сдвигаются на 1-2 бита влево (зависит от раунда).
 * - Склеиваются в один 56-битный вектор.
 * - Выполняется сжатие ключа до 48-битного вектора (по таблице
 *   преобразований, описанной в спецификации DES).
 */
static uint64_t gen_round_key(uint64_t *C0, uint64_t *D0, int round_num)
{
    // Сдвиги влево при формировании раундовых ключей
    static const int KEY_ROTATIONS[TOTAL_ROUNDS] = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    int round_shift = KEY_ROTATIONS[round_num];

    *C0 = rotate_left(*C0, round_shift, 28);
    *D0 = rotate_left(*D0, round_shift, 28);
    uint64_t round_key_56 = *C0 << 28 | *D0;

    // P-бокс перестановка (сжатие) ключа
    uint64_t round_key_48 = 0;
    for (int j = 0; j < 48; ++j) {
        round_key_48 <<= 1;
        round_key_48 |= get_bit(round_key_56, KEY_FINAL_TRANSFORMS[j] - 1, 56);
    }
    return round_key_48;
}


/**
 * Трансформирует начальный 64-битовый ключ в 16 раундовых ключей.
 *
 * Генерация ключей выполняется CPU, т.к. сравнительно простая и
 * плохо параллелится.
 *
 * Выполняется следующим образом:
 * - 64-битный ключ трансформируется в 56-битный, удаляются биты
 *   коррекции.
 * - 56-битный ключ делится на два 28-битных вектора - C0 и D0.
 * - Формируются раундовые ключи.
 */
static void make_rounds_keys(uint64_t init_key, uint64_t *result_arr)
{
    // Трансформируем 64-битный ключ в 56-битный
    uint64_t key = 0;
    for (int i = 0; i < 56; ++i) {
        key <<= 1;
        key |= get_bit(init_key, KEY_INIT_TRANSFORMS[i] - 1, 64);
    }

    // Делим ключ на C0 (старшие разряды) и D0 (младшие), по 28 бит каждый
    uint64_t C0 = (key >> 28) & 0x0FFFFFFF;
    uint64_t D0 = (key >>  0) & 0x0FFFFFFF;

    // Формируем раундовые ключи сдвигами влево на 1-2 бита.
    for (int i = 0; i < TOTAL_ROUNDS; ++i) {
        result_arr[i] = gen_round_key(&C0, &D0, i);
    }
}


/**
 * Выполняет шифрование 64-битного блока данных.
 * 1. Выполняется начальная перестановка данных.
 * 2. Выполняются раунды Фейстеля.
 * 3. Выполняется финальная перестановка данных.
 */
__device__
static uint64_t des_process_block(uint64_t block, uint64_t *round_keys,
                                  int encr_or_decr)
{
    uint64_t cipher = apply_permutation(block, true);

    uint64_t L = cipher >> 32 & 0xFFFFFFFF;
    uint64_t R = cipher >>  0 & 0xFFFFFFFF;

    for (int round_num = 0; round_num < TOTAL_ROUNDS; ++round_num) {
        uint64_t key;
        if (encr_or_decr == ENCRYPTION) {
            key = round_keys[round_num];
        } else {
            key = round_keys[TOTAL_ROUNDS - round_num - 1];
        }

        uint64_t nextR = L ^ feistel_function(R, key);
        L = R;
        R = nextR;
    }

    // После последнего раунда R и L не переставляются
    cipher = R << 32 | L;

    cipher = apply_permutation(cipher, false);

    return cipher;
}


/**
 * Выполняет шифрование или расшифровку массива данных.
 * all_data - весь массив данных,
 * len - количество блоков,
 * round_keys - раундовые ключи,
 * encr_or_decr - шифрование или расшифрование.
 */
__global__
static void map_des(uint64_t *all_data, int len, uint64_t *round_keys,
                    int encr_or_decr)
{
    int idx = blockIdx.x * THREADS_PER_BLOCK + threadIdx.x;
    if (idx < len) {
        all_data[idx] = des_process_block(
            all_data[idx], round_keys, encr_or_decr);
    }
}


/**
 * Выполняет шифрование или расшифровку массива данных.
 * 3-DES EDE.
 * all_data - весь массив данных,
 * len - количество блоков,
 * round_keys - раундовые ключи,
 * encr_or_decr - шифрование или расшифрование.
 */
__global__
static void map_3des_ede(uint64_t *all_data, int len, uint64_t *round_keys,
                         int encr_or_decr)
{
    int idx = blockIdx.x * THREADS_PER_BLOCK + threadIdx.x;
    if (idx < len) {
        uint64_t block = all_data[idx];
        if (encr_or_decr == ENCRYPTION) {
            block = des_process_block(
                block, &round_keys[0], ENCRYPTION);
            block = des_process_block(
                block, &round_keys[TOTAL_ROUNDS], DECRYPTION);
            block = des_process_block(
                block, &round_keys[2 * TOTAL_ROUNDS], ENCRYPTION);
        } else if (encr_or_decr == DECRYPTION) {
            block = des_process_block(
                block, &round_keys[0], DECRYPTION);
            block = des_process_block(
                block, &round_keys[TOTAL_ROUNDS], ENCRYPTION);
            block = des_process_block(
                block, &round_keys[2 * TOTAL_ROUNDS], DECRYPTION);
        }
        all_data[idx] = block;
    }
}


/**
 * Запускает процесс шифрования на GPU.
 * Инициализирует и очищает память, передает управление GPU и т.д.
 * data - массив данных (на хосте) для шифрования/расшифровки,
 * len - количество блоков для шифрования,
 * round_keys - раундовые ключи (на хосте),
 * encr_or_decr - шифрование или расшифровка,
 * strategy - алгоритм шифрования: DES, 3DES(EDE)...
 */
static void des_run_device(uint64_t *data, size_t len, uint64_t *round_keys,
                           int encr_or_decr, int strategy)
{
    // TODO: проверять успешность выделения памяти

    // Аллоцируем память для самих даных.
    uint64_t *data_dev = NULL;
    cudaMalloc((void **) &data_dev, len * sizeof(uint64_t));
    cudaMemcpy(
        data_dev, data,
        len * sizeof(uint64_t),
        cudaMemcpyHostToDevice
    );

    // Аллоцируем память для ключей раундов
    uint64_t *round_keys_dev = NULL;
    // TODO: Выделять константную память!
    cudaMalloc((void **) &round_keys_dev, 3 * TOTAL_ROUNDS * sizeof(uint64_t));
    cudaMemcpy(
        round_keys_dev, round_keys,
        3 * TOTAL_ROUNDS * sizeof(uint64_t),
        cudaMemcpyHostToDevice
    );

    // Запускаем обработку на девайсе
    uint64_t run_threads = min((int) len, THREADS_PER_BLOCK);
    uint64_t run_blocks = (len + run_threads - 1) / len;

    if (strategy == STRATEGY_SIMPLE_DES) {
        map_des<<<run_blocks, run_threads>>>(
            data_dev, len, round_keys_dev, encr_or_decr
        );
    } else if (strategy == STRATEGY_3DES_EDE) {
        map_3des_ede<<<run_blocks, run_threads>>>(
            data_dev, len, round_keys_dev, encr_or_decr
        );
    }

    // Копируем данные с девайса на хост и освобождаем память
    cudaMemcpy(
        data, data_dev,
        len * sizeof(uint64_t),
        cudaMemcpyDeviceToHost
    );
    cudaFree(round_keys_dev);
    cudaFree(data_dev);
}


/**
 * Выполняет шифрование блока данных по алгоритму DES.
 * data - массив 64-битных блоков данных,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ.
 */
void des_encrypt(uint64_t *data, size_t len, uint64_t key)
{
    uint64_t round_keys[3 * TOTAL_ROUNDS] = {0};
    make_rounds_keys(key, round_keys);
    des_run_device(data, len, round_keys,
                   ENCRYPTION, STRATEGY_SIMPLE_DES);
}


/**
 * Выполняет расшифровку блока данных по алгоритму DES.
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ,
 */
void des_decrypt(uint64_t *data, size_t len, uint64_t key)
{
    uint64_t round_keys[3 * TOTAL_ROUNDS] = {0};
    make_rounds_keys(key, round_keys);
    des_run_device(data, len, round_keys,
                   DECRYPTION, STRATEGY_SIMPLE_DES);
}


/**
 * Выполняет расшифровку блока данных по алгоритму 3DES(EDE).
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * keys - 3 64-битнх ключа,
 */
void tdes_ede_encrypt(uint64_t *data, size_t len, const uint64_t *keys)
{
    uint64_t round_keys[3 * TOTAL_ROUNDS] = {0};

    for (int i = 0; i < 3; ++i) {
        make_rounds_keys(keys[i], &round_keys[i * TOTAL_ROUNDS]);
    }
    des_run_device(data, len, round_keys,
                   ENCRYPTION, STRATEGY_3DES_EDE);
}


/**
 * Выполняет расшифровку блока данных по алгоритму 3DES(EDE).
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * keys - 3 64-битнх ключа,
 */
void tdes_ede_decrypt(uint64_t *data, size_t len, const uint64_t *keys)
{
    uint64_t round_keys[3 * TOTAL_ROUNDS] = {0};
    for (int i = 0; i < 3; ++i) {
        make_rounds_keys(keys[3 - i - 1], &round_keys[i * TOTAL_ROUNDS]);
    }
    des_run_device(data, len, round_keys,
                   DECRYPTION, STRATEGY_3DES_EDE);
}

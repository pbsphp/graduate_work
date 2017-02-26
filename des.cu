#include <stdbool.h>
#include <stdint.h>


#define THREADS_PER_BLOCK 500
#define BLOCKS_PER_ITERATION 1000
#define DATA_PER_ITERATION (THREADS_PER_BLOCK * BLOCKS_PER_ITERATION)


#define ENCRYPTION 1
#define DECRYPTION 2


// У DES 16 раундов
#define TOTAL_ROUNDS 16


/**
 * Возвращает index'ный бит из number, нумерация битов справа
 */
#define GET_BIT_TAIL(number, index) ((unsigned) ((number) >> (index)) & 1)


/**
 * Возвращает #index бит из number.
 * Нумерация битов слева. Параметр total_bits - разрядность числа.
 */
#define GET_BIT(number, index, total_bits) \
    (GET_BIT_TAIL((number), (total_bits) - (index) - 1))


/**
 * Циклический сдвиг влево
 */
#define ROTATE_LEFT(number, bits, total_bits) \
    ( \
        ( \
            (number) << (bits) | (number) >> ((total_bits) - (bits)) \
        ) & ((1 << (total_bits)) - 1) \
    )


// Начальная и конечная перестановки
__device__
static const int INITIAL_PERMUTATION[] = {
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
static const int FINAL_PERMUTATION[] = {
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
static const int S_BOX[8][4][TOTAL_ROUNDS] = {
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


// Сдвиги влево при формировании раундовых ключей
static const int KEY_ROTATIONS[TOTAL_ROUNDS] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
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
 * Выполняет начальную или конечную перестановку битов.
 */
__device__
static uint64_t apply_permutation(uint64_t data, bool initial)
{
    const int *ip = initial ? INITIAL_PERMUTATION : FINAL_PERMUTATION;

    uint64_t result = 0;
    for (int i = 0; i < 64; ++i) {
        result <<= 1;
        result |= GET_BIT(data, ip[i] - 1, 64);
    }
    return result;
}


/**
 * Выполняет P-бокс расширение
 */
__device__
static uint64_t pbox_transform(uint64_t data)
{
    uint64_t result = 0;
    for (int i = 0; i < 48; ++i) {
        result <<= 1;
        result |= GET_BIT(data, P_BOX[i] - 1, 32);
    }
    return result;
}


/**
 * Выполняет P-бокс преобразование в раундовой функции des
 */
__device__
static uint64_t round_pbox_transform(uint64_t data)
{
    uint64_t result = 0;
    for (int i = 0; i < 32; ++i) {
        result <<= 1;
        result |= GET_BIT(data, ROUND_P_BOX[i] - 1, 32);
    }
    return result;
}


/**
 * Выполняет S-бокс преобразование
 */
__device__
static uint64_t sbox_transform(uint64_t data, int vec_num)
{
    // 1 и 6 биты - номер строки, 2, 3, 4, 5 - столбца.
    int row = ((data >> 4) & 2) | (data & 1);
    int col = (data >> 1) & 0xF;
    return S_BOX[vec_num][row][col];
}


/**
 * Функция DES - шифрует 32 бита информации внутри раунда
 */
__device__
static uint64_t des_round_fn(uint64_t data, uint64_t subkey)
{
    // Расширяем блок с 32 до 48 бит
    uint64_t result = pbox_transform(data);

    // XOR с ключом
    result ^= subkey;

    // Делим 48-битное число на 8 векторов по 6 бит каждый
    uint64_t vectors[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 7; i >= 0; --i) {
        vectors[i] = result & 0x3F;
        result >>= 6;
    }

    // Выполняем S-бокс преобразования
    for (int i = 0; i < 8; ++i) {
        vectors[i] = sbox_transform(vectors[i], i);
    }

    // После S-бокс преобразования получаем 8 4-битных векторов,
    // которые объединяются в один 32-битный.
    result = 0;
    for (int i = 0; i < 8; ++i) {
        result <<= 4;
        result |= vectors[i];
    }
    result = round_pbox_transform(result);
    return result;
}


/**
 * Трансформирует начальный 64-битовый ключ в 16 раундовых ключей.
 *
 * Генерация ключей выполняется CPU, т.к. сравнительно простая и
 * плохо параллелится.
 */
static void make_rounds_keys(uint64_t init_key, uint64_t *result_arr,
                             int encr_or_decr)
{
    // Трансформируем 64-битный ключ в 56-битный
    uint64_t key = 0;
    for (int i = 0; i < 56; ++i) {
        key <<= 1;
        key |= GET_BIT(init_key, KEY_INIT_TRANSFORMS[i] - 1, 64);
    }

    // Делим ключ на C0 (старшие разряды) и D0 (младшие), по 28 бит каждый
    uint64_t C0 = (key >> 28) & 0x0FFFFFFF;
    uint64_t D0 = (key >>  0) & 0x0FFFFFFF;

    // Формируем раундовые ключи сдвигами влево на 1-2 бита.
    for (int i = 0; i < TOTAL_ROUNDS; ++i) {
        C0 = ROTATE_LEFT(C0, KEY_ROTATIONS[i], 28);
        D0 = ROTATE_LEFT(D0, KEY_ROTATIONS[i], 28);
        uint64_t round_key_56 = C0 << 28 | D0;

        // P-бокс перестановка (сжатие) ключа
        uint64_t round_key_48 = 0;
        for (int j = 0; j < 48; ++j) {
            round_key_48 <<= 1;
            round_key_48 |= GET_BIT(round_key_56, KEY_FINAL_TRANSFORMS[j] - 1, 56);
        }

        // При расшифровке ключи раундов в обратном порядке
        if (encr_or_decr == ENCRYPTION) {
            result_arr[i] = round_key_48;
        } else {
            result_arr[TOTAL_ROUNDS - i - 1] = round_key_48;
        }
    }
}


/**
 * Выполняет шифрование одного блока
 * data - массив всех данных для шифрования,
 * len - длина массива для шифрования (количество блоков)
 * round_keys - массив раундовых ключей
 */
__global__
static void encrypt_with_round_keys(uint64_t *data, size_t len,
                                    uint64_t *round_keys)
{
    int idx = blockIdx.x * THREADS_PER_BLOCK + threadIdx.x;
    if (idx < len) {
        // Начальная перестановка
        uint64_t cipher = apply_permutation(data[idx], true);

        uint64_t L = cipher >> 32 & 0xFFFFFFFF;
        uint64_t R = cipher >>  0 & 0xFFFFFFFF;

        // Раунды преобразования Фейстеля
        for (int round_num = 0; round_num < TOTAL_ROUNDS; ++round_num) {
            uint64_t key = round_keys[round_num];
            uint64_t nextR = L ^ des_round_fn(R, key);
            L = R;
            R = nextR;
        }

        // После последнего раунда R и L не переставляются
        cipher = R << 32 | L;
        cipher = apply_permutation(cipher, false);
        data[idx] = cipher;
    }
}


/**
 * Запускает процесс шифрования на GPU.
 * Инициализирует память и т.п.
 */
static void des_run_device(uint64_t *data, size_t len, uint64_t *round_keys)
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
    cudaMalloc((void **) &round_keys_dev, TOTAL_ROUNDS * sizeof(uint64_t));
    cudaMemcpy(
        round_keys_dev, round_keys,
        TOTAL_ROUNDS * sizeof(uint64_t),
        cudaMemcpyHostToDevice
    );

    // Запускаем обработку на девайсе
    uint64_t run_threads = min((int) len, THREADS_PER_BLOCK);
    uint64_t run_blocks = (len + run_threads - 1) / len;
    encrypt_with_round_keys<<<run_blocks, run_threads>>>(
        data_dev, len, round_keys_dev
    );

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
 * Выполняет шифрование блока данных.
 * data - массив 64-битных блоков данных,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ.
 */
void des_encrypt(uint64_t *data, size_t len, uint64_t key)
{
    uint64_t round_keys[TOTAL_ROUNDS] = {0};
    make_rounds_keys(key, round_keys, ENCRYPTION);

    des_run_device(data, len, round_keys);
}


/**
 * Выполняет расшифровку блока данных.
 * data - массив 64-битных блоков шифротекста,
 * len - длина массива (количество блоков),
 * key - 64-битный ключ,
 */
void des_decrypt(uint64_t *data, size_t len, uint64_t key)
{
    uint64_t reversed_round_keys[TOTAL_ROUNDS] = {0};
    make_rounds_keys(key, reversed_round_keys, DECRYPTION);

    des_run_device(data, len, reversed_round_keys);
}

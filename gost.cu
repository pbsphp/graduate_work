#include <stdint.h>


#define ENCRYPTION 1
#define DECRYPTION 2

#define THREADS_PER_BLOCK 500
#define BLOCKS_PER_ITERATION 1000
#define DATA_PER_ITERATION (THREADS_PER_BLOCK * BLOCKS_PER_ITERATION)


/**
 * Таблица S-box для выполнения преобразований.
 * Значения таблицы не описываются в ГОСТ.
 */
__device__
static const uint8_t S_BOX[8][16] = {
    {0x04, 0x0A, 0x09, 0x02, 0x0D, 0x08, 0x00, 0x0E, 0x06, 0x0B, 0x01, 0x0C, 0x07, 0x0F, 0x05, 0x03},
    {0x0E, 0x0B, 0x04, 0x0C, 0x06, 0x0D, 0x0F, 0x0A, 0x02, 0x03, 0x08, 0x01, 0x00, 0x07, 0x05, 0x09},
    {0x05, 0x08, 0x01, 0x0D, 0x0A, 0x03, 0x04, 0x02, 0x0E, 0x0F, 0x0C, 0x07, 0x06, 0x00, 0x09, 0x0B},
    {0x07, 0x0D, 0x0A, 0x01, 0x00, 0x08, 0x09, 0x0F, 0x0E, 0x04, 0x06, 0x0C, 0x0B, 0x02, 0x05, 0x03},
    {0x06, 0x0C, 0x07, 0x01, 0x05, 0x0F, 0x0D, 0x08, 0x04, 0x0A, 0x09, 0x0E, 0x00, 0x03, 0x0B, 0x02},
    {0x04, 0x0B, 0x0A, 0x00, 0x07, 0x02, 0x01, 0x0D, 0x03, 0x06, 0x08, 0x05, 0x09, 0x0C, 0x0F, 0x0E},
    {0x0D, 0x0B, 0x04, 0x01, 0x03, 0x0F, 0x05, 0x09, 0x00, 0x0A, 0x0E, 0x07, 0x06, 0x08, 0x02, 0x0C},
    {0x01, 0x0F, 0x0D, 0x00, 0x05, 0x07, 0x0A, 0x04, 0x09, 0x02, 0x03, 0x0E, 0x06, 0x0B, 0x08, 0x0C}
};


/**
 * Циклически сдвигает 32-битное число на 11 бит влево
 */
__device__
static inline uint32_t rotate_left_11(uint32_t x)
{
    return (x << 11) | (x >> (32 - 11));
}


/**
 * Выполняет замену бит в числе по S-боксу.
 * 32-битное число делится на части по 4 бита, каждая такая
 * часть заменяется по S-боксу.
 */
__device__
static inline uint32_t sbox_transform(uint32_t val)
{
    uint32_t in = val;
    uint32_t result = 0;
    for (int i = 0; i < 8; ++i) {
        int tetra = in & 0x0F;
        in >>= 4;
        tetra = S_BOX[i][tetra];
        result |= tetra << (4 * i);
    }
    return result;
}


/**
 * Функция сети Фейстеля
 * num - входной блок,
 * key - ключ.
 *
 * F(A, Kn), где A - левый полублок предыдущего раунда,
 *               Kn - ключ текущего раунда.
 * A складывается с Kn по модулю 2^32, проходит S-box преобразование,
 * сдвигается на 11 бит влево.
 */
__device__
static inline uint32_t feistel_function(uint32_t num, uint32_t key)
{
    return rotate_left_11(sbox_transform(num + key));
}


/**
 * Выполняет шифрование или расшифровку блока данных.
 * block - входной блок данных,
 * keys - 256-битный ключ (массив 8-битных данных),
 * encr_or_decr - шифрование или расшифровка.
 *
 * Шифрование выполняется с помощью сети Фейстеля.
 * Входной блок разделяется на две половины по 32-бита,
 * далее следуют 32 раунда:
 * A[n+1] = B[n] XOR F(A[n], K[n])
 * B[n+1] = A[n],
 * где A[n] и B[n] - половинки предыдущего раунда,
 * A[n+1] и B[n+1] - половинки текущего раунда,
 * F(A[n], K[n]) - функция для сети Фейстеля.
 * См. feistel_function().
 * После последнего раунда половинки не меняются местами и объединяются
 * в один 64-битный блок - результат шифрования или дешифрования.
 * Входной 256-битный ключ разбивается на подключи по 32-бита: K1 .. K8.
 * При шифровании ключи для 1..24 раундов циклично используются по порядку, а
 * начиная с 24 раунда в обратном порядке. При расшифровке для 1..8 раундов
 * ключи используются в прямом порядке, начиная с 8 раунда в обратном.
 */
__device__
static uint64_t process_block(uint64_t block, const uint32_t *keys,
                              int encr_or_decr)
{
    uint32_t left = (block >> 32) & 0xFFFFFFFF;
    uint32_t right = block & 0xFFFFFFFF;

    for (int round_num = 0; round_num < 32; ++round_num) {
        uint32_t key;
        if (encr_or_decr == ENCRYPTION && round_num >= 24 ||
                encr_or_decr == DECRYPTION && round_num >= 8) {
            key = keys[7 - (round_num % 8)];
        } else {
            key = keys[round_num % 8];
        }

        uint32_t next_left = right ^ feistel_function(left, key);
        right = left;
        left = next_left;
    }

    return ((uint64_t) right << 32) | left;
}


/**
 * Обрабатывает блоки на устройстве
 */
__global__
static void map_gost(uint64_t *data, int len, const uint32_t *key,
                     int encr_or_decr)
{
    int idx = blockIdx.x * THREADS_PER_BLOCK + threadIdx.x;
    if (idx < len) {
        data[idx] = process_block(data[idx], key, encr_or_decr);
    }
}


/**
 * Запускает шифрование на девайсе
 */
static void gost_run_device(uint64_t *data, int len, const uint32_t *key,
                            int encr_or_decr)
{
    uint64_t *data_dev;
    cudaMalloc((void **) &data_dev, len * sizeof(uint64_t));
    cudaMemcpy(
        data_dev, data, len * sizeof(uint64_t),
        cudaMemcpyHostToDevice
    );

    uint64_t *key_dev;
    cudaMalloc((void **) &key_dev, sizeof(uint32_t) * 8);
    cudaMemcpy(
        key_dev, key, sizeof(uint32_t) * 8,
        cudaMemcpyHostToDevice
    );

    // Запускаем обработку на девайсе
    int run_threads = min((int) len, THREADS_PER_BLOCK);
    int run_blocks = (len + run_threads - 1) / len;
    map_gost<<<run_blocks, run_threads>>>(
        data_dev, len, (const uint32_t *) key_dev, encr_or_decr
    );

    cudaMemcpy(
        data, data_dev, len * sizeof(uint64_t),
        cudaMemcpyDeviceToHost
    );

    cudaFree(data_dev);
    cudaFree(key_dev);
}


/**
 * Выполняет шифрование по ГОСТ 28147-89
 * data - массив 64-битных данных для шифрования,
 * len - количество 64-битных блоков,
 * key - 256-битный ключ (массив 32-битных частей).
 */
void gost_encrypt(uint64_t *data, int len, const uint32_t *key)
{
    gost_run_device(data, len, key, ENCRYPTION);
}


/**
 * Выполняет расшифровку по ГОСТ 28147-89
 * cipher - массив 64-битных блоков шифротекста,
 * len - количество 64-битных блоков,
 * key - 256-битный ключ (массив 32-битных частей).
 */
void gost_decrypt(uint64_t *cipher, int len, const uint32_t *key)
{
    gost_run_device(cipher, len, key, DECRYPTION);
}

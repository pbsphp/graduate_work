/**
 * Вспомогаельный функционал, который не относится к бизнес-логике.
 */


#ifndef HELPERS_H
#define HELPERS_H


#include <stdint.h>
#include <stdio.h>


/**
 * Округляет число в большую сторону до кратности base.
 *
 * Например:
 * round_up_to_base(30, 8) = 32,
 * round_up_to_base(1234, 100) = 1300
 */
static inline int round_up_to_base(int num, int base)
{
    return base * ((num + base - 1) / base);
}


/**
 * Возвращает размер файла
 */
static long get_file_size(FILE *f)
{
    long curr_pos = ftell(f);
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, curr_pos, SEEK_SET);
    return fsize;
}


/**
 * Меняет операнды местами.
 */
__device__ __host__
static inline void swap32(uint32_t *a, uint32_t *b)
{
    uint32_t tmp = *a;
    *a = *b;
    *b = tmp;
}


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


#endif

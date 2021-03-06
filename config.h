/**
 * Настройки и константы
 */

#ifndef CONFIG_H
#define CONFIG_H


/**
 * Блок данного размера будет прочитан из файла, загружен в память
 * и обработан, после чего записан в выходной файл.
 *
 * Ограничение обусловлено объемом доступной памяти.
 * Необходима кратность 16.
 */
#define WORK_MEM_SIZE 1024 * 1024 * 200


/**
 * Количество тредов запускаемых в одном блоке.
 *
 * Ограничено возможностями GPU. Желательна кратность 32.
 */
#define THREADS_PER_BLOCK 256


/**
 * Количество одновременно зпускаемых блоков.
 *
 * Ограничено возможностями GPU.
 */
#define BLOCKS_PER_GRID 4

#endif

#ifndef __BENZENE_MUTATION_H__
#define __BENZENE_MUTATION_H__

#include <sys/types.h>
#include <stdint.h>

/*
 * mutation logics based on honggfuzz: https://github.com/google/honggfuzz
 */
void mangle_init();
void mangle(char* buf, size_t len);
void mangle_str(char* seed, size_t seed_len);
void mangle_strlen(char* seed, size_t seed_len);
void mangle_clear(char* seed, size_t seed_len);
size_t mangle_get_index(size_t max);
uint64_t util_rndGet(uint64_t min, uint64_t max);
uint64_t util_rnd64(void);

#endif
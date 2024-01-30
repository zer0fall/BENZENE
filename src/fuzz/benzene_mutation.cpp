#include "benzene_mutation.h"

#include <stdint.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

/* TEMP_FAILURE_RETRY, but for all OSes */
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(exp)                                                                    \
    ({                                                                                             \
        __typeof(exp) _rc;                                                                         \
        do {                                                                                       \
            _rc = (exp);                                                                           \
        } while (_rc == -1 && errno == EINTR);                                                     \
        _rc;                                                                                       \
    })
#endif /* ifndef TEMP_FAILURE_RETRY */

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))
#endif /* ifndef ARRAYSIZE */

#define MANGLE_STRLEN_MAX 128

static __thread pthread_once_t rndThreadOnce = PTHREAD_ONCE_INIT;
static __thread uint64_t       rndState[2];


ssize_t files_readFromFd(int fd, uint8_t* buf, size_t fileSz) {
    size_t readSz = 0;
    while (readSz < fileSz) {
        ssize_t sz = TEMP_FAILURE_RETRY(read(fd, &buf[readSz], fileSz - readSz));
        if (sz == 0) {
            break;
        }
        if (sz < 0) {
            return -1;
        }
        readSz += sz;
    }
    return (ssize_t)readSz;
}

static void util_rndInitThread(void) {
    int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC));
    if (fd == -1) {
        fprintf(stderr, "Couldn't open /dev/urandom for reading\n");
        exit(-1);
    }
    if (files_readFromFd(fd, (uint8_t*)rndState, sizeof(rndState)) != sizeof(rndState)) {
        fprintf(stderr, "Couldn't read '%zu' bytes from /dev/urandom", sizeof(rndState));
        exit(-1);
    }
    close(fd);
}

/*
 * xoroshiro128plus by David Blackman and Sebastiano Vigna
 */
static inline uint64_t util_RotL(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t util_InternalRnd64(void) {
    const uint64_t s0     = rndState[0];
    uint64_t       s1     = rndState[1];
    const uint64_t result = s0 + s1;
    s1 ^= s0;
    rndState[0] = util_RotL(s0, 55) ^ s1 ^ (s1 << 14);
    rndState[1] = util_RotL(s1, 36);

    return result;
}

uint64_t util_rnd64(void) {
    // pthread_once(&rndThreadOnce, util_rndInitThread);
    // util_rndInitThread();
    return util_InternalRnd64();
}

uint64_t util_rndGet(uint64_t min, uint64_t max) {
    if (min > max) {
        fprintf(stderr, "min > max (min : %lx, max : %lx)\n", min, max);
        exit(-1);
    }

    if (max == UINT64_MAX) {
        return util_rnd64();
    }

    return ((util_rnd64() % (max - min + 1)) + min);
}

void util_rndBuf(uint8_t* buf, size_t sz) {
    // pthread_once(&rndThreadOnce, util_rndInitThread);
    if (sz == 0) {
        return;
    }
    for (size_t i = 0; i < sz; i++) {
        buf[i] = (uint8_t)(util_InternalRnd64() >> 40);
    }
}

/* Generate random printable ASCII */
uint8_t util_rndPrintable(void) {
    return util_rndGet(32, 126);
}

void util_rndBufPrintable(uint8_t* buf, size_t sz) {
    for (size_t i = 0; i < sz; i++) {
        buf[i] = util_rndPrintable();
    }
}

/*
 * Get a random value <1:max>, but prefer smaller ones
 * Based on an idea by https://twitter.com/gamozolabs
 */
static inline size_t mangle_getLen(size_t max) {
    if (max == 0) {
        fprintf(stderr, "mangle_getLen() : error\n");
        exit(-1);
    }
    if (max == 1) {
        return 1;
    }

    /* Give 50% chance the the uniform distribution */
    if (util_rnd64() & 1) {
        return (size_t)util_rndGet(1, max);
    }

    /* effectively exprand() */
    return (size_t)util_rndGet(1, util_rndGet(1, max));
}


/* Prefer smaller values here, so use mangle_getLen() */
static inline size_t mangle_getOffSet(size_t len) {
    return mangle_getLen(len) - 1;
}

static inline void mangle_Overwrite(
    char* seed, size_t seed_len, size_t off, const uint8_t* src, size_t copy_len) 
{
    if (copy_len == 0) {
        return;
    }
    size_t maxToCopy = seed_len - off;
    if (copy_len > maxToCopy) {
        copy_len = maxToCopy;
    }

    memmove(&seed[off], src, copy_len);
}



static inline void mangle_UseValue(char* seed, size_t seed_len, const uint8_t* val, size_t len) {
    mangle_Overwrite(seed, seed_len, mangle_getOffSet(seed_len), val, len);
}


static inline void mangle_UseValueAt(
    char* seed, size_t seed_len, size_t off, const uint8_t* val, size_t len) {
        mangle_Overwrite(seed, seed_len, off, val, len);
}

static void mangle_ASCII(char* seed, size_t seed_len) {
    size_t off = mangle_getOffSet(seed_len);
    size_t len = mangle_getLen(seed_len - off);

    util_rndBufPrintable((uint8_t*)&seed[off], len);
}

static void mangle_ASCIINum(char* seed, size_t seed_len) {
    size_t len = util_rndGet(0, seed_len);

    char buf[seed_len];
    snprintf(buf, sizeof(buf), "%-19ld", (int64_t)util_rnd64());

    mangle_UseValue(seed, seed_len, (const uint8_t*)&buf, len);
}

static void mangle_ASCIINumChange(char* seed, size_t seed_len) {
    size_t off = mangle_getOffSet(seed_len);

    /* Find a digit */
    for (; off < seed_len; off++) {
        if (isdigit(seed[off])) {
            break;
        }
    }
    size_t left = seed_len - off;
    if (left == 0) {
        return;
    }
    
    size_t   len = 0;
    uint64_t val = 0;
    /* 20 is maximum lenght of a string representing a 64-bit unsigned value */
    for (len = 0; len < left; len++) {
        char c = seed[off + len];
        if (!isdigit(c)) {
            break;
        }
        val *= 10;
        val += (c - '0');
    }

    switch (util_rndGet(0, 7)) {
        case 0:
            val++;
            break;
        case 1:
            val--;
            break;
        case 2:
            val *= 2;
            break;
        case 3:
            val /= 2;
            break;
        case 4:
            val = util_rnd64();
            break;
        case 5:
            val += util_rndGet(1, 256);
            break;
        case 6:
            val -= util_rndGet(1, 256);
            break;
        case 7:
            val = ~(val);
            break;
        default:
            fprintf(stderr, "Invalid choice\n");
    };

    char buf[20];
    snprintf(buf, sizeof(buf), "%-19lu", val);

    mangle_UseValueAt(seed, seed_len, off, (const uint8_t*)&buf, len);
}


static void mangle_Bytes(char* seed, size_t seed_len) {
    uint16_t buf;

    buf = util_rnd64();

    /* Overwrite with random 1-2-byte values */
    size_t toCopy = util_rndGet(1, 2);

    mangle_UseValue(seed, seed_len, (const uint8_t*)&buf, toCopy);
}


static void mangle_RandomBuf(char* seed, size_t seed_len) {
    size_t off = mangle_getOffSet(seed_len);
    size_t len = mangle_getLen(seed_len - off);

    util_rndBuf((uint8_t*)&seed[off], len);
}

static void mangle_MemClr(char* seed, size_t seed_len) {
    size_t off = mangle_getOffSet(seed_len);
    size_t len = mangle_getLen(seed_len - off);

    memset(&seed[off], 0, len);
}

static void mangle_Bit(char* seed, size_t seed_len) {
    size_t off = mangle_getOffSet(seed_len);
    seed[off] ^= (uint8_t)(1U << util_rndGet(0, 7));
}

static void mangle_NegByte(char* seed, size_t seed_len) {
    size_t off = mangle_getOffSet(seed_len);

    seed[off] = ~(seed[off]);
}


static inline void mangle_AddSubWithRange(
    char* seed, size_t seed_len, size_t off, size_t varLen, uint64_t range) {
    int64_t delta = (int64_t)util_rndGet(0, range * 2) - (int64_t)range;

    switch (varLen) {
        case 1: {
            seed[off] += delta;
            break;
        }
        case 2: {
            int16_t val;
            memcpy(&val, &seed[off], sizeof(val));
            if (util_rnd64() & 0x1) {
                val += delta;
            } else {
                /* Foreign endianess */
                val = __builtin_bswap16(val);
                val += delta;
                val = __builtin_bswap16(val);
            }
            mangle_Overwrite(seed, seed_len, off, (uint8_t*)&val, varLen);
            break;
        }
        case 4: {
            int32_t val;
            memcpy(&val, &seed[off], sizeof(val));
            if (util_rnd64() & 0x1) {
                val += delta;
            } else {
                /* Foreign endianess */
                val = __builtin_bswap32(val);
                val += delta;
                val = __builtin_bswap32(val);
            }
            mangle_Overwrite(seed, seed_len, off, (uint8_t*)&val, varLen);
            break;
        }
        case 8: {
            int64_t val;
            memcpy(&val, &seed[off], sizeof(val));
            if (util_rnd64() & 0x1) {
                val += delta;
            } else {
                /* Foreign endianess */
                val = __builtin_bswap64(val);
                val += delta;
                val = __builtin_bswap64(val);
            }
            mangle_Overwrite(seed, seed_len, off, (uint8_t*)&val, varLen);
            break;
        }
        default: {
            fprintf(stderr, "Unknown variable length size: %zu", varLen);
            exit(-1);            
        }
    }
}


static void mangle_int32(char* seed, size_t seed_len) {
    size_t varLen = 4;

    if (varLen > seed_len)
        varLen = seed_len;

    size_t rand_int = mangle_getLen(((uint64_t)1 << (8*varLen)) - 1);

    memcpy(seed, &rand_int, varLen);
    memset(&seed[varLen], 0, seed_len - varLen);    
}

static void mangle_int16(char* seed, size_t seed_len) {
    size_t varLen = 2;
    
    if (seed_len < 2) {
        varLen = 1;
    }
    
    size_t rand_int = mangle_getLen(((uint64_t)1 << (8*varLen)) - 1);

    memcpy(seed, &rand_int, varLen);
    memset(&seed[varLen], 0, seed_len - varLen);
}

// make 1-byte integer
static void mangle_int8(char* seed, size_t seed_len) {
    size_t small_int = mangle_getLen(0xFF);

    seed[0] = (char)small_int;

    memset(&seed[1], 0, seed_len - 1);
}

static void mangle_IntIncDec(char* seed, size_t seed_len) {
    int64_t delta = (int64_t)util_rndGet(0, 1) ? 1 : -1;
    
    switch (seed_len) {
        case 1: {
            *(char*)seed += delta;
            break;
        }
        case 2: {
            *(int16_t*)seed += delta;
            break;
        }
        case 4: {
            *(int32_t*)seed += delta;
            break;
        }
        case 8: {
            *(int64_t*)seed += delta;
            break;
        }
        default: {
            fprintf(stderr, "Unknown variable length size: %zu", seed_len);
            exit(-1);            
        }
    }
}

void mangle_clear(char* seed, size_t seed_len) {
    memset(seed, 0, seed_len);
}

void mangle(char* seed, size_t seed_len) {
    // static void (*const mangleFuncs[])(run_t * run, bool printable) = {
    //     mangle_Shrink,
    //     mangle_Expand,
    //     mangle_Bit,
    //     mangle_IncByte,
    //     mangle_DecByte,
    //     mangle_NegByte,
    //     mangle_AddSub,
    //     mangle_MemSet,
    //     mangle_MemClr,
    //     mangle_MemSwap,
    //     mangle_MemCopy,
    //     mangle_Bytes,
    //     mangle_ASCIINum,
    //     mangle_ASCIINumChange,
    //     mangle_ByteRepeat,
    //     mangle_Magic,
    //     mangle_StaticDict,
    //     mangle_ConstFeedbackDict,
    //     mangle_RandomBuf,
    //     mangle_Splice,
    // };

    static void (*const mangleFuncs[])(char* seed, size_t seed_len) = {
        mangle_Bytes,
        mangle_RandomBuf,
        mangle_clear,
        mangle_int32,
        mangle_int16,
        mangle_int8
    };


    uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleFuncs) - 1);
    mangleFuncs[choice](seed, seed_len);

}

void mangle_strlen(char* seed, size_t seed_len) {
    size_t max_len = seed_len > MANGLE_STRLEN_MAX ? MANGLE_STRLEN_MAX : seed_len;
    size_t len = mangle_get_index(max_len);

    // nullify the string over the `len`
    memset(&seed[len], 0, seed_len - len);
    return;
}

void mangle_str(char* seed, size_t seed_len) {
    static void (*const mangleFuncs[])(char* seed, size_t seed_len) = {
        mangle_clear,
        mangle_ASCII,
        mangle_ASCII,
        mangle_ASCIINum,
        mangle_ASCIINumChange,
    };

    uint64_t choice = util_rndGet(0, ARRAYSIZE(mangleFuncs) - 1);
    mangleFuncs[choice](seed, seed_len);
}

void mangle_init() {
    util_rndInitThread();
}

size_t mangle_get_index(size_t max) {
    return mangle_getLen(max) - 1;
}
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct worker {
    uint64_t seed;
    uint64_t rounds;
    uint64_t result;
};

__attribute__((noinline)) static uint64_t cpu(uint64_t value, uint64_t rounds) {
    for (uint64_t round = 0; round < rounds; ++round) {
        value ^= value >> 12;
        value ^= value << 25;
        value ^= value >> 27;
        value *= UINT64_C(0x2545f4914f6cdd1d);
    }
    return value;
}

static void *run_worker(void *argument) {
    struct worker *worker = argument;
    worker->result = cpu(worker->seed, worker->rounds);
    return NULL;
}

__attribute__((noinline)) static uint64_t allocations(uint64_t rounds) {
    unsigned char *retained[128];
    for (size_t index = 0; index < 128; ++index) {
        retained[index] = malloc(65536);
        if (!retained[index]) { perror("malloc"); exit(2); }
        memset(retained[index], (int)index, 65536);
    }
    uint64_t checksum = 0;
    for (uint64_t round = 0; round < rounds; ++round) {
        size_t length = 64 + (size_t)(round % 2048);
        unsigned char *bytes = malloc(length);
        if (!bytes) { perror("malloc"); exit(2); }
        memset(bytes, (int)(round % 256), length);
        __asm__ volatile ("" : : "r"(bytes) : "memory");
        checksum += bytes[0] + bytes[length - 1];
        free(bytes);
    }
    __asm__ volatile ("" : : "r"(retained) : "memory");
    for (size_t index = 0; index < 128; ++index) free(retained[index]);
    return checksum;
}

int main(int argc, char **argv) {
    if (argc != 3 || !argv[2][0] || argv[2][0] == '-' || isspace((unsigned char)argv[2][0])) {
        fprintf(stderr, "usage: workload {cpu|threads|alloc} POSITIVE_ROUNDS\n");
        return 2;
    }
    char *end;
    errno = 0;
    uint64_t rounds = strtoull(argv[2], &end, 10);
    if (errno || *end || !rounds) { fprintf(stderr, "invalid rounds\n"); return 2; }
    uint64_t result;
    if (strcmp(argv[1], "cpu") == 0) result = cpu(1, rounds);
    else if (strcmp(argv[1], "alloc") == 0) result = allocations(rounds);
    else if (strcmp(argv[1], "threads") == 0) {
        pthread_t threads[4];
        struct worker workers[4];
        for (size_t index = 0; index < 4; ++index) {
            workers[index] = (struct worker){index + 1, rounds, 0};
            if (pthread_create(&threads[index], NULL, run_worker, &workers[index])) return 2;
        }
        result = 0;
        for (size_t index = 0; index < 4; ++index) {
            if (pthread_join(threads[index], NULL)) return 2;
            result += workers[index].result;
        }
    } else { fprintf(stderr, "unknown mode\n"); return 2; }
    printf("%" PRIu64 "\n", result);
    return 0;
}

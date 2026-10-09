#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile uint64_t result;

__attribute__((noinline)) void pyroclast_parity_hot_loop(void) {
    uint64_t value = 1;
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) exit(1);
    do {
        for (unsigned int i = 0; i < 100000; ++i) value = value * 6364136223846793005ULL + 1;
        result = value;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) exit(1);
    } while (now.tv_sec - start.tv_sec < 5);
}

__attribute__((noinline)) void pyroclast_parity_other_process(void) {
    uint64_t value = 7;
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) exit(1);
    do {
        for (unsigned int i = 0; i < 100000; ++i) value = value * 2862933555777941757ULL + 3;
        result = value;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) exit(1);
    } while (now.tv_sec - start.tv_sec < 5);
}

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    FILE *identity = fopen(argv[1], "w");
    if (!identity) return 1;
    if (fprintf(identity, "%ld\n", (long)getpid()) < 0 || fclose(identity) != 0) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        pyroclast_parity_other_process();
        _exit(0);
    }
    pyroclast_parity_hot_loop();
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

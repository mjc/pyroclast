#include <errno.h>
#include <signal.h>
#include <unistd.h>

static void acknowledge(int signal) {
    (void)signal;
    int saved_errno = errno;
    if (write(STDOUT_FILENO, "I", 1) != 1) _exit(2);
    errno = saved_errno;
}

int main(void) {
    struct sigaction action = {0};
    action.sa_handler = acknowledge;
    if (sigemptyset(&action.sa_mask) || sigaction(SIGINT, &action, NULL)) return 3;
    sigset_t blocked;
    if (sigprocmask(SIG_BLOCK, NULL, &blocked) || sigismember(&blocked, SIGINT)) return 4;
    if (write(STDOUT_FILENO, "R", 1) != 1) return 5;
    for (;;) pause();
}

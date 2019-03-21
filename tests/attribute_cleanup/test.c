#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h> 

void handler(int);

#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void _reset_errno_(int *saved_errno) {
        errno = *saved_errno;
}

#define PROTECT_ERRNO _cleanup_(_reset_errno_) __attribute__((unused)) int _saved_errno_ = errno

int main (void)
{
    static const struct sigaction sa={
        .sa_handler=handler
    };

    sigaction(SIGINT, &sa, NULL);

    return 0;
}

void handler(int signum)
{
   PROTECT_ERRNO;
   kill(signum,0);
}


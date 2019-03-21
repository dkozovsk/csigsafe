#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h> 

void handler(int);

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
    (void)signum;
    _exit(4);
}


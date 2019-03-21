#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h> 

void handler(int);
void my_exit(int num)
{
   if(num==9)
      _exit(42);
   else
      _exit(num);
}

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
    kill(signum,0);
    my_exit(9);
}


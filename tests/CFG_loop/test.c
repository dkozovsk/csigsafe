#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h> 

void handler(int);

int main (void)
{
    struct sigaction sa={
        .sa_handler=handler
    };

    sigaction(SIGINT, &sa, NULL);

    return 0;
}

void handler(int signum)
{
   int i = 42;
   while(i==42)
   {
      if (signum==SIGTERM)
         return;
      if (signum==SIGSTOP)
         i=9;
      kill(SIGKILL,0);
   }
   _exit(9);
}


#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

void handler(int signum);

int main (void)
{
    signal(SIGINT, handler);

    return 0;
}

void handler(int signum)
{
   const int store_errno=errno;
   errno=store_errno;
   kill(SIGKILL,0);
   return;
   
}

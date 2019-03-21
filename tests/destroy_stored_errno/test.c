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
   int store_errno=errno;
   kill(SIGKILL,0);
   store_errno=42;
   errno=store_errno;
   return;
   
}

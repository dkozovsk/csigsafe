#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

void handler_ok(int signum);
void handler_wrong(int signum);

int main (void)
{
    signal(SIGINT, handler_ok);
    signal(SIGTERM, handler_wrong);

    return 0;
}

void handler_wrong(int signum)
{
   kill(SIGKILL,0);
   return;
   
}

void handler_ok(int signum)
{
   int store_errno=errno;
   kill(SIGKILL,0);
   errno=store_errno;
   abort();
    
}

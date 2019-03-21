#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

void my_fnc0(void);
void my_fnc1(void);
void my_fnc2(void);
void my_fnc3(void);
void handler(int);

void some_handler(int signum)
{
    (void)signum;
    my_fnc0();
}

void set_handler(int signum,void func(int))
{
    set_handler(signum,func);
    signal(signum,func);
}

void my_fnc0(void)
{
	my_fnc1();
}
void my_fnc1(void)
{
	my_fnc2();
}
void my_fnc2(void)
{
	my_fnc3();
}
void my_fnc3(void)
{
	printf("aaaa\n");
	abort();
}


int main (void)
{
    set_handler(SIGTERM, some_handler);
    signal(SIGINT, handler);

    return 0;
}

void handler(int signum)
{
    (void)signum;
    printf("something");
    abort();
}

test:
	gcc -c -g -O4 -Wno-parentheses -Wno-format-security -finline-functions -findirect-inlining ./sig.c -o /dev/null -fplugin=./../../csigsafe.so $(HOST_CFLAGS) 2>./test.err 

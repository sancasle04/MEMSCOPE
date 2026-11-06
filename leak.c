/* Test program: leaks 1 MB every second so memscope watch has something to find. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    printf("leak running, PID %d\n", getpid());
    fflush(stdout);
    for (;;) {
        char *p = malloc(1024 * 1024);
        if (!p)
            return 1;
        memset(p, 1, 1024 * 1024);   /* touch it so it counts in RSS */
        sleep(1);
    }
}

#include <stdlib.h>
#include <stdio.h>

int f(int x) {
    int p = 0xDEAD;
    p += 3 * x + 0xBEEF;
    return p;
}

int main()
{
    int a[10];
    int i;
    for(i=0; i<10; i++) {
        a[i] = f(i);
        if (a[i] == 0) {
            a[i] = 0xBAADF00D;
        }
    }
    return 0;
}

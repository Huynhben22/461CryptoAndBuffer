#include<string.h>
#include<stdio.h>

void foo(int a, int b, char *str) {
    char buffer1[64];
    char buffer2[128];
    int x, y;

    x = 1;
    strcpy(buffer1, str);
    printf("buffer copied\n");
    y = 2;
}

void boo(char *str) {
    int a = 1;
    int b = 2;
    foo(a, b, str);
}

void main() {
    int i;
    char long_str[20];
    for (i = 0; i < 20; i++) {
        long_str[i] = '3';
    }
    boo(long_str);
    i = 23;
    printf("i = %d\n", i);
}

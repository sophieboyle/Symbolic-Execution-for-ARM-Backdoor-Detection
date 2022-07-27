#include <stdlib.h>
#include <stdio.h>

int main(){
    FILE *f = fopen("/etc/passwd", "w");
    char str[] = "hello";
    fwrite(str, 1, sizeof(str), f);
    fclose(f);
}
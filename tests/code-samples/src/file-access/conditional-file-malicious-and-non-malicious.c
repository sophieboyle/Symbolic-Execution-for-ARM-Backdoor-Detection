#include <stdlib.h>
#include <stdio.h>

int main(){
    int b = 0;
    scanf("%d", &b);

    if (b){
            FILE *f = fopen("/etc/passwd", "r");
            char str[] = "hello";
            fwrite(str, 1, sizeof(str), f);
            fclose(f);
    } else {
            FILE *f = fopen("/etc/example", "r");
            char str[] = "hello";
            fwrite(str, 1, sizeof(str), f);
            fclose(f);
    }
}
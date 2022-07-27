#include <stdlib.h>
#include <stdio.h>

int main(){
    FILE *f1 = fopen("/etc/passwd", "r");
    fclose(f1);
    FILE *f2 = fopen("/etc/shadow", "r");
    fclose(f2);
}
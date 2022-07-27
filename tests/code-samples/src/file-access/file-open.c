#include <stdlib.h>
#include <stdio.h>

int main(){
    FILE *f = fopen("/etc/passwd", "r");
    fclose(f);
}
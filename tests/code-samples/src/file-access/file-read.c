#include <stdlib.h>
#include <stdio.h>

int main(){
    FILE *f = fopen("/etc/passwd", "r");
    char buffer[1000] = "NULL";
    fread(buffer, sizeof(buffer), 1, f);
    fclose(f);
}
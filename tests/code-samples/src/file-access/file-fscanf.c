#include <stdlib.h>
#include <stdio.h>

int main(){
    FILE *f = fopen("/etc/passwd", "r");
    char buffer[1000] = "NULL";
    fscanf(f, "%s", buffer);
    fclose(f);
}
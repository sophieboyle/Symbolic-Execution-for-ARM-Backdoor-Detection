#include <stdlib.h>
#include <stdio.h>

int main(){
    int b = 0;
    scanf("%d", &b);

    int c = 0;
    scanf("%d", &c);

    if (b){
        printf("Hello");
        if (c){
            FILE *f = fopen("/etc/passwd", "r");
            fclose(f);
        } else {
            FILE *f = fopen("/etc/shadow", "r");
            fclose(f); 
        }
    } else {
        printf("Dead");
    }
}
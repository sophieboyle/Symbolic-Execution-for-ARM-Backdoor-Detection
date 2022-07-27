#include <stdlib.h>

int main(){
    static char cmd[] =
                        "\x2f\x62\x69\x6e"
                        "\x2f\x73\x68";
    static char cmd2[] = "/bin/ksh";

    system(cmd);
    system(cmd2);
}
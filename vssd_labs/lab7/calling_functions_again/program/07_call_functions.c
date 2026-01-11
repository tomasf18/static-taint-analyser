// gcc -m32 -Wall -Wextra -ggdb -no-pie

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFFER_LEN 128

void win() {
    printf("You win!");
    system("cat /home/ctf/flag");
}

void vuln() {
    char buffer[BUFFER_LEN] = {0};
    read(0, buffer, BUFFER_LEN-1);

    printf(buffer);
    puts("Bye!\n");
}

int main() {
    vuln();
}

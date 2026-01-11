// gcc -m32 -Wall -Wextra -ggdb -no-pie

#include <stdio.h>
#include <unistd.h>
#include "get_flag.h"

#define BUFFER_LEN 128

unsigned int target_before = 0;
unsigned int target = 0;
unsigned int target_after = 0;

void vuln() {
    char buffer[BUFFER_LEN] = {0};
    read(0, buffer, BUFFER_LEN-1);

    printf(buffer);

    if (target == 0xdeadbeef) {
        printf("Success! You hit the target!\n");
        printf("Here is your flag: %s\n", get_flag());
    } else {
        printf("Oops, not quite! The target was: 0xdeadbeef\nCurrent value is 0x%08x\n", target);
    }
}

int main() {
    vuln();
}

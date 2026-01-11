// gcc -m32 -Wall -Wextra -ggdb -no-pie

#include <stdio.h>
#include <unistd.h>
#include "get_flag.h"

#define BUFFER_LEN 64

char buffer[BUFFER_LEN] = {0};

void vuln() {
    // Never prints secret_value
    char *secret_value = get_flag();
    printf(buffer);
}

int main() {
    read(0, buffer, BUFFER_LEN-1);
    vuln();
}

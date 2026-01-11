#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char* argv[]){
    static char passwd[8] = "s4fe";
    char buffer[64];

    printf("VAR passwd@ %p:%s VAR buffer@ %p\n", &passwd, passwd, &buffer);
    
    fgets(buffer, 64, stdin);
    printf(buffer);

    if (strcmp(passwd, "c4ge") == 0)
        printf("You WIN!!\n");
    else
        printf("Sorry. Try again.\nYour password is %s instead of c4ge\n", passwd);
}
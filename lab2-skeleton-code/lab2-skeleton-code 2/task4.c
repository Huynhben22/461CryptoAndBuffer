#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int check_authentication(char *password) {
    int auth_flag = 0;
    char password_buffer[16];

    strcpy(password_buffer, password);

    if(strcmp(password_buffer, "realpassword") == 0)
        auth_flag = 1;

    return auth_flag;
}

int main(int argc, char *argv[]) {
    int i = 0;

    if(argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        exit(0);
    }

    printf("arg: %s\n", argv[1]);

    i = check_authentication(argv[1]);

    printf("checking auth return\n");

    if (i == 0) {
        printf("\nAccess Denied.\n");
        return 0;
    }

    printf("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    printf(" Access Granted.\n");
    printf("-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
    return 0;
}

// TODO: Confirm that a binary compiled from this code still works for this task.
// The code has been tweaked after generating the target (vulnerable) binary.

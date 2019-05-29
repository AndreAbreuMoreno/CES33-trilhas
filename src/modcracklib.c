 #include <stdio.h>
 #ifdef HAVE_LIBXCRYPT
 #include <xcrypt.h>
 #elif defined(HAVE_CRYPT_H)
 #include <crypt.h>
 #endif
 #include <unistd.h>
 #include <stdlib.h>
 #include <string.h>
 #include <syslog.h>
 #include <stdarg.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <ctype.h>
 #include <limits.h>
 #include <pwd.h>
 #include <security/pam_modutil.h>

 #ifdef MIN
 #undef MIN
 #endif
 /*
  * here, we make a definition for the externally accessible function
  * in this file (this definition is required for static a module
  * but strongly encouraged generally) it is used to instruct the
  * modules include file to define the function prototypes.
  */

 #define PAM_SM_PASSWORD

 #include <security/pam_modules.h>
 #include <security/_pam_macros.h>
 #include <security/pam_ext.h>

 /* argument parsing */
 #define PAM_DEBUG_ARG       0x0001

 struct cracklib_options {
     int retry_times;
     int length;
     int dig_credit;
     int reject_user;
     int enforce_for_root;
 };

 #define CO_RETRY_TIMES  1
 #define CO_LENGTH       5
 #define CO_LENGTH_BASE  1
 #define CO_DIG_CREDIT   5
 #define CO_MIN_WORD_LENGTH 5

static int pam_parse(pam_handle_t *pamh, struct cracklib_options *opt,
int argc, const char **argv){
    int ctrl=0;

    /* step through arguments */
    for(ctrl=0; argc-- > 0; ++argv){
        char *ep = NULL;

        /* generic options */
        if (!strcmp(*argv,"debug"))
            ctrl |= PAM_DEBUG_ARG;
        else if(!strncmp(*argv,"type=",5))
            pam_set_item (pamh, PAM_AUTHTOK_TYPE, *argv+5);
        else if(!strncmp(*argv,"retry=",6)){
            opt->retry_times = strtol(*argv+6,&ep,10);
            if(!ep || (opt->retry_times < 1))
                opt->retry_times = CO_RETRY_TIMES;
        } else if (!strncmp(*argv,"difignore=",10)) {
            /* just ignore */
        } else if (!strncmp(*argv,"len=",4)) {
            opt->length = strtol(*argv+4,&ep,10);
            if (!ep || (opt->length < CO_LENGTH_BASE))
                opt->length = CO_LENGTH_BASE;
        } else if (!strncmp(*argv,"dcredit=",8)) {
            opt->dig_credit = strtol(*argv+8,&ep,10);
            if (!ep)
                opt->dig_credit = CO_DIG_CREDIT;
        } else if (!strncmp(*argv,"reject_username",15)) {
            opt->reject_user = 1;
        } else if (!strncmp(*argv,"enforce_for_root",16)) {
            opt->enforce_for_root = 1;
        } else if (!strncmp(*argv,"authtok_type",12)) {
            /* for pam_get_authtok, ignore */;
        } else if (!strncmp(*argv,"use_authtok",11)) {
            /* for pam_get_authtok, ignore */;
        } else if (!strncmp(*argv,"use_first_pass",14)) {
            /* for pam_get_authtok, ignore */;
        } else if (!strncmp(*argv,"try_first_pass",14)) {
            /* for pam_get_authtok, ignore */;
        } else {
            pam_syslog(pamh,LOG_ERR,"pam_parse: unknown option; %s",*argv);
        }
    }

    return ctrl;
}

/* Helper functions*/
char *password_check(pam_handle_t *pamh, struct cracklib_options *opt,
const char *oldp, const char *newp, const char *user) {
    char *msg = NULL;
    int i = 0;
    int number_digits = 0;

    if(strlen(newp) != opt->length)
        msg = "wrong number of characters";
    else{
        while(i < opt->length){
            if(isdigit(newp[i]))
                number_digits++;
            i++;
        }
        if(number_digits != opt->dig_credit)
            msg = "wrong amount of digits";
    }

    return msg;
}

 static int pam_unix_approve_pass(pam_handle_t *pamh, unsigned int ctrl,
     struct cracklib_options *opt, const char *pass_old, const char *pass_new){
     char *msg = NULL;
     const char *user;
     int retval;

     pam_syslog(pamh, LOG_NOTICE, "test if user typed nothing or the same passwd as before");
     if (pass_new == NULL || (pass_old && !strcmp(pass_old,pass_new))) {
         if (ctrl & PAM_DEBUG_ARG)
             pam_syslog(pamh, LOG_DEBUG, "bad authentication token");
         pam_error(pamh, "%s", pass_new == NULL ?
            "No password supplied":"Password unchanged");
         return PAM_AUTHTOK_ERR;
     }
     pam_syslog(pamh, LOG_NOTICE, "test if user typed nothing or the same passwd as before passed");

     pam_syslog(pamh, LOG_NOTICE, "test if we can get username");
     retval = pam_get_user(pamh, &user, NULL);
     if (retval != PAM_SUCCESS || user == NULL) {
         if (ctrl & PAM_DEBUG_ARG)
             pam_syslog(pamh,LOG_ERR,"Can not get username");
         return PAM_AUTHTOK_ERR;
     }
     pam_syslog(pamh, LOG_NOTICE, "test if we can get username passed");
     /*
      * if one wanted to hardwire authentication token strength
      * checking this would be the place
     */
     msg = password_check(pamh, opt, pass_old, pass_new, user);
     pam_syslog(pamh, LOG_NOTICE, "msg=password_check retorna: %s", msg);
     if (msg) {
         if (ctrl & PAM_DEBUG_ARG)
             pam_syslog(pamh, LOG_NOTICE,
                "new passwd fails strength check: %s", msg);
         pam_error(pamh, "BAD PASSWORD: %s", msg);
         return PAM_AUTHTOK_ERR;
     };
     return PAM_SUCCESS;

 }

 /* The Main Thing (by Cristian Gafton, CEO at this module :-)
  * (stolen from http://home.netscape.com)
  */
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){
    unsigned int ctrl;
    struct cracklib_options options;

    pam_syslog(pamh,LOG_NOTICE, "pam_sm_chauthtok called");

    memset(&options, 0, sizeof(options));
    options.retry_times = CO_RETRY_TIMES;
    options.length = CO_LENGTH;
    options.dig_credit = CO_DIG_CREDIT;

    ctrl = pam_parse(pamh, &options, argc, argv);

    if(flags & PAM_PRELIM_CHECK){
         /* Check for passwd dictionary */
         /* We cannot do that, since the original path is compiled
        into the cracklib library and we don't know it.  */
        return PAM_SUCCESS;
    } else if (flags & PAM_UPDATE_AUTHTOK) {
        int retval;
        const void *oldtoken;
        int tries;

        pam_syslog(pamh,LOG_NOTICE,"Do update");

        retval = pam_get_item (pamh, PAM_OLDAUTHTOK, &oldtoken);
        if(retval != PAM_SUCCESS){
            if(ctrl & PAM_DEBUG_ARG)
                pam_syslog(pamh,LOG_ERR,"Can not get old passwd");
            oldtoken = NULL;
        }

        tries = 0;
        while (tries < options.retry_times) {
            char *crack_msg;
            const char *newtoken = NULL;

            tries++;

            /* Planned modus operandi:
            * Get a passwd.
            * Verify it against cracklib.
            * If okay get it a second time.
            * Check to be the same with the first one.
            * set PAM_AUTHTOK and return
            */

            retval = pam_get_authtok_noverify(pamh, &newtoken, NULL);
            if (retval != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_ERR, "pam_get_authtok_noverify returned error: %s", pam_strerror(pamh, retval));
                continue;
            } else if (newtoken == NULL) {      /* user aborted password change, quit */
                pam_syslog(pamh,LOG_NOTICE,"Negocio chato");
                return PAM_AUTHTOK_ERR;
            }

            /* check it for strength too... */
            pam_syslog(pamh,LOG_NOTICE, "check for strength");
            retval = pam_unix_approve_pass(pamh, ctrl, &options, oldtoken, newtoken);
            if(retval != PAM_SUCCESS){
                if(getuid() || options.enforce_for_root || (flags & PAM_CHANGE_EXPIRED_AUTHTOK)){
                    pam_set_item(pamh, PAM_AUTHTOK, NULL);
                    retval = PAM_AUTHTOK_ERR;
                    continue;
                }
            }

            retval = pam_get_authtok_verify(pamh, &newtoken, NULL);
            if (retval != PAM_SUCCESS) {
                pam_syslog(pamh, LOG_NOTICE, "pam_get_authtok_verify returned error: %s", pam_strerror (pamh, retval));
                pam_set_item(pamh, PAM_AUTHTOK, NULL);
                continue;
            } else if(newtoken == NULL) {      /* user aborted password change, quit */
                return PAM_AUTHTOK_ERR;
            }
            return PAM_SUCCESS;
        }

        pam_set_item (pamh, PAM_AUTHTOK, NULL);

        /* if we have only one try, we can use the real reason,
        else say that there were too many tries. */
        if (options.retry_times > 1)
            return PAM_MAXTRIES;
        else
            return retval;
    } else {
        if (ctrl & PAM_DEBUG_ARG)
            pam_syslog(pamh, LOG_NOTICE, "UNKNOWN flags setting %02X",flags);
        return PAM_SERVICE_ERR;
    }

    /* Not reached */
    return PAM_SERVICE_ERR;
}

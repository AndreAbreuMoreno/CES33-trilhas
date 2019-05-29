/*
  * pam_cracklib module
  */

 /*
  * 0.9. switch to using a distance algorithm in similar()
  * 0.86.  added support for setting minimum numbers of digits, uppers,
  *        lowers, and others
  * 0.85.  added six new options to use this with long passwords.
  * 0.8. tidied output and improved D(()) usage for debugging.
  * 0.7. added support for more obscure checks for new passwd.
  * 0.6. root can reset user passwd to any values (it's only warned)
  * 0.5. supports retries - 'retry=N' argument
  * 0.4. added argument 'type=XXX' for 'New XXX password' prompt
  * 0.3. Added argument 'debug'
  * 0.2. new password is feeded to cracklib for verify after typed once
  * 0.1. First release
  */

 /*
  * Modification for long password systems (>8 chars).  The original
  * module had problems when used in a md5 password system in that it
  * allowed too short passwords but required that at least half of the
  * bytes in the new password did not appear in the old one.  this
  * action is still the default and the changes should not break any
  * current user. This modification adds 6 new options, one to set the
  * number of bytes in the new password that are not in the old one,
  * the other five to control the length checking, these are all
  * documented (or will be before anyone else sees this code) in the PAM
  * S.A.G. in the section on the cracklib module.
*/

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

#define CRACKLIB_DICTS NULL

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
     int diff_ok;
     int min_length;
     int dig_credit;
     int up_credit;
     int low_credit;
     int oth_credit;
     int min_class;
     int max_repeat;
     int max_sequence;
     int max_class_repeat;
     int reject_user;
     int gecos_check;
     int enforce_for_root;
     char *cracklib_dictpath;
 };

 #define CO_RETRY_TIMES  1
 #define CO_DIFF_OK      5
 #define CO_MIN_LENGTH   5
 #define CO_MIN_LENGTH_BASE 5
 #define CO_DIG_CREDIT   5
 #define CO_UP_CREDIT    0
 #define CO_LOW_CREDIT   0
 #define CO_OTH_CREDIT   0
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
        } else if(!strncmp(*argv,"difok=",6)) {
            opt->diff_ok = strtol(*argv+6,&ep,10);
            if(!ep || (opt->diff_ok < 0))
                opt->diff_ok = CO_DIFF_OK;
        } else if (!strncmp(*argv,"difignore=",10)) {
            /* just ignore */
        } else if (!strncmp(*argv,"minlen=",7)) {
            opt->min_length = strtol(*argv+7,&ep,10);
            if (!ep || (opt->min_length < CO_MIN_LENGTH_BASE))
                opt->min_length = CO_MIN_LENGTH_BASE;
        } else if (!strncmp(*argv,"dcredit=",8)) {
            opt->dig_credit = 5;
        } else if (!strncmp(*argv,"ucredit=",8)) {
            opt->up_credit = strtol(*argv+8,&ep,10);
            if (!ep)
                opt->up_credit = 0;
        } else if (!strncmp(*argv,"lcredit=",8)) {
            opt->low_credit = strtol(*argv+8,&ep,10);
            if (!ep)
                opt->low_credit = 0;
        } else if (!strncmp(*argv,"ocredit=",8)) {
            opt->oth_credit = strtol(*argv+8,&ep,10);
            if (!ep)
                opt->oth_credit = 0;
        } else if (!strncmp(*argv,"minclass=",9)) {
            opt->min_class = strtol(*argv+9,&ep,10);
            if (!ep)
                opt->min_class = 0;
            if(opt->min_class > 4)
                opt->min_class = 4;
            } else if (!strncmp(*argv,"maxrepeat=",10)) {
                opt->max_repeat = strtol(*argv+10,&ep,10);
                if (!ep)
                    opt->max_repeat = 0;
            } else if (!strncmp(*argv,"maxsequence=",12)) {
                opt->max_sequence = strtol(*argv+12,&ep,10);
                if (!ep)
                    opt->max_sequence = 0;
            } else if (!strncmp(*argv,"maxclassrepeat=",15)) {
                opt->max_class_repeat = strtol(*argv+15,&ep,10);
                if (!ep)
                    opt->max_class_repeat = 0;
            } else if (!strncmp(*argv,"reject_username",15)) {
                opt->reject_user = 1;
            } else if (!strncmp(*argv,"gecoscheck",10)) {
                opt->gecos_check = 1;
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

    if(strlen(newp) != 5){
        msg = "5 characters required";
        pam_syslog(pamh, LOG_NOTICE, "mensagem com mais ou menos de 5 carac: %s", msg);
    } else{
        while(i < 5){
            if(!isdigit(newp[i])){
                msg = "only digits allowed";
                pam_syslog(pamh, LOG_NOTICE, "%s", msg);
            }
            i++;
        }
    }
    pam_syslog(pamh, LOG_NOTICE, "sem mensagem: %s", msg);

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
    options.diff_ok = CO_DIFF_OK;
    options.min_length = CO_MIN_LENGTH;
    options.dig_credit = CO_DIG_CREDIT;
    options.up_credit = CO_UP_CREDIT;
    options.low_credit = CO_LOW_CREDIT;
    options.oth_credit = CO_OTH_CREDIT;
    options.cracklib_dictpath = CRACKLIB_DICTS;

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
                pam_syslog(pamh,LOG_NOTICE, "vovo juju");
                pam_syslog(pamh, LOG_NOTICE, "pam_get_authtok_verify returned error: %s", pam_strerror (pamh, retval));
                pam_set_item(pamh, PAM_AUTHTOK, NULL);
                continue;
            } else if(newtoken == NULL) {      /* user aborted password change, quit */
                pam_syslog(pamh, LOG_ERR, "gesonel");
                return PAM_AUTHTOK_ERR;
            }
            pam_syslog(pamh, LOG_ERR, "jorel");
            return PAM_SUCCESS;
        }
        pam_syslog(pamh, LOG_NOTICE, "returning because maxtries reached");

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

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

const struct pam_conv conv = {
	misc_conv,
	NULL
};

int main(int argc, char *argv[]) {
	pam_handle_t* pamh = NULL;
	int retval;
	const char* user = "ninguem";

	if(argc != 2) {
		printf("Favor, inserir usuario\n");
		exit(1);
	}

	user = argv[1];

	retval = pam_start("check_user", user, &conv, &pamh);

	// Verificar se o usuario existe
	if (retval == PAM_SUCCESS) {
		retval = pam_authenticate(pamh, 0);
	}

	// Verificar se a conta pode ser utilizada
	if (retval == PAM_SUCCESS) {
		printf("Senha valida.\n");
		retval = pam_acct_mgmt(pamh, 0);
	}

	// Verificar se senha e usuario conferem
	if (retval == PAM_SUCCESS) {
		printf("Autenticado\n");
	} else {
		printf("Nao Autenticado \n");
	}

	// finaliza
	if (pam_end(pamh, retval) != PAM_SUCCESS) {
		pamh = NULL;
		printf("Falha na autenticacao\n");
		exit(1);
	}

	return retval == PAM_SUCCESS ? 0 : 1;
}

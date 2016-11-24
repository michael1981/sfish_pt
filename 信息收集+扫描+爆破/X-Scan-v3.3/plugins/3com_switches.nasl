#
# This script was written by Patrik Karlsson <patrik.karlsson@ixsecurity.com>
# Enhancements by Tomi Hanninen
#
# Changes by Tenable:
# - Revised CVSS score and updated severity.


include("compat.inc");

if(description)
{
   script_id(10747);
   script_version("$Revision: 1.19 $");
   script_cve_id("CVE-1999-0508");
   script_xref(name:"OSVDB", value:"620");

   script_name(english:"3Com Superstack 3 Switch Multiple Default Accounts");
   script_summary(english:"Logs into 3Com Superstack 3 switches with default passwords.");

 script_set_attribute(attribute:"synopsis", value:
"The remote switch has accounts with default passwords set." );
 script_set_attribute(attribute:"description", value:
"The 3Com Superstack 3 switch has the default passwords set.

The attacker could use these default passwords to gain remote
access to your switch and then reconfigure the switch. These
passwords could also be potentially used to gain sensitive
information about your network from the switch." );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for the accounts." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2001-2009 Patrik Karlsson");
   script_family(english:"Misc.");
   script_require_ports(23);
 
   exit(0);
}

include('telnet_func.inc');

port = 23; # the port can't be changed

banner = get_telnet_banner(port:port);
if ( "Login : " >!< banner ) exit(0);

login[0] = string("monitor");
login[1] = string("manager");
login[2] = string("security");
login[3] = string("admin");

password[0] = string("monitor");
password[1] = string("manager");
password[2] = string("security");
password[3] = string("");

bfound = 0;

res = string("Standard passwords were found on this 3Com Superstack switch.\n");
res = res + string("The passwords found are:\n\n");

if(get_port_state(port))
{

 for ( i=0; i<4; i = i + 1 )
 {
     soc = open_sock_tcp(port);
     if(soc)
     {
        r = recv(socket:soc, length:160);
        if("Login: " >< r)
        {
	    tmp = string(login[i], "\r\n");
	    send(socket:soc, data:tmp);
	    r = recv_line(socket:soc, length:2048);
            tmp = string(password[i], "\r\n");
	    send(socket:soc, data:tmp);
	    r = recv(socket:soc, length:4096);

	    if ( "logout" >< r )
	    {
		bfound = 1;
		res = string(res, login[i], ":", login[i], "\n");
     	    }

        }
   
      close(soc);

  }

 }

 res = string(res, "\nSolution : Telnet to this switch immediately and ",
 		  "change the passwords above.\n",
 		  "Risk factor : High\n");

 if ( bfound == 1 )
 {
      security_hole(port:23, data:res);
 }
}

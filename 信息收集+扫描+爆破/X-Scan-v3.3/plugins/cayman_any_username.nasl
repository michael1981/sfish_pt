#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID
#
# Vulnerability found by Russell Handorf <rhandorf@mail.russells-world.com>


include("compat.inc");


if(description)
{
 script_id(10724);
 script_cve_id("CVE-2001-1430");
 script_bugtraq_id(3017);
 script_xref(name:"OSVDB", value:"602");
 script_version ("$Revision: 1.17 $");
 script_name(english:"Cayman DSL Router Single Character String Authentication Bypass");
 script_summary(english:"Tries to login using default credentials");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router is secured with a default username and password."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote host appears to be a Cayman DSL router.  This device\n",
     "contains an insecure user account - it was possible to login with a\n",
     "username of '{' and no password."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2001-07/0183.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Give the account a strong password."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");
 
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_require_ports(23);
 script_dependencies("os_fingerprint.nasl");
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');
include('global_settings.inc');


os = get_kb_item("Host/OS");
if ( ! os && ! thorough_tests ) exit(0);
if ( "Cayman" >!< os ) exit(0);

port = 23;
login = raw_string(0x7D);
if(get_port_state(port))
{
 banner = get_telnet_banner(port:port);
 if ( ! banner || "login" >!< banner ) exit(0);

 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_negotiate(socket:soc);
  if("login" >< buf)
  	{
	 r = recv(socket:soc, length:2048);
	 b = buf + r;
	 send(socket:soc, data:string(login, "\r\n"));
	 r = recv(socket:soc, length:2048);
	 send(socket:soc, data:string("\r\n"));
	 r = recv(socket:soc, length:4096);
	 if("completed login" >< b)security_hole(port);
	}
  close(soc);
 }
}

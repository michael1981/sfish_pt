#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11757);
 script_bugtraq_id(7900);
 script_xref(name:"OSVDB", value:"50481");
 script_xref(name:"Secunia", value:"9036");

 script_version ("$Revision: 1.8 $");
 
 script_name(english:"NGC Active FTPServer 2002 Multiple Command Remote DoS");
 script_summary(english:"NGC ActiveFTP check.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Active FTP server, a shareware
FTP server for Windows-based systems.

There is a flaw in the version of ActiveFTP which may allow an
attacker to crash this service remotely by sending an overly long
argument to various FTP commands (USER, CWD, and more). The attack can
only be performed without authentication through the USER command.

A successful exploit will result in a denial of service and may
potentially allow the attacker to execute arbitry code in the context
of the affected application.");
 
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/secunia/2003-q2/0593.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("find_service_3digits.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(!get_port_state(port)) exit(0);


#
# This service can not be crashed reliably, we only rely on the banner 
# (ie: no safe_checks/no safe checks).
#

banner = get_ftp_banner(port:port);
if(!banner) exit(0);
if("Welcome to NGC Active FTPServer" >< banner) { security_hole(port); exit(0); }

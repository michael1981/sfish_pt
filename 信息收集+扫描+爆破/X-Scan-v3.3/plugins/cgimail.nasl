#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11721);
 script_bugtraq_id(1623);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2000-0726");
 script_xref(name:"OSVDB", value:"5763");
 
 script_name(english:"Stalkerlab Mailers CGIMail.exe Arbitrary File Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The CGI 'CgiMail.exe' exists on this webserver.
Some versions of this file are vulnerable to remote exploit.

An attacker can use this flaw to gain access to confidential
data or further escalate their privileges." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-08/0371.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Checks for the cgimail.exe file";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 John Lampe");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/cgimail.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
}
 
if (flag) security_note(port);

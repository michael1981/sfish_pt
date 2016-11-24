#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11722);
 script_bugtraq_id(3216);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-1150");
 script_xref(name:"OSVDB", value:"6140");
 script_name(english:"Trend Micro Virus Buster cgiWebupdate.exe Arbitrary File Retrieval");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a CGI application that is affected
by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The CGI 'cgiWebupdate.exe' exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.

An attacker can use this hole to gain access to confidential data
or escalate their privileges on the web server.

*** Note that Nessus solely relied on the existence of the 
*** cgiWebupdate.exe file." );
 script_set_attribute(attribute:"solution", value:
"Trend Micro has released a patch that addresses this issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );


script_end_attributes();

 
 summary["english"] = "Checks for the cgiWebupdate.exe file";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); 
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 John Lampe");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("find_service1.nasl", "http_version.nasl");
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
   if(is_cgi_installed_ka(item:string(dir, "/cgiWebupdate.exe"), port:port)) {
  	security_warning(port);
	exit(0);
	}
   } 

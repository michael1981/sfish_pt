#
# (C) Tenable Network Security, Inc.
#

# References:
# http://marc.info/?l=bugtraq&m=100463639800515&w=2


include("compat.inc");

if(description)
{
 script_id(11107);
 script_version ("$Revision: 1.14 $");
 script_cve_id("CVE-2001-0849");
 script_bugtraq_id(3495);
 script_xref(name:"OSVDB", value:"13981");

 script_name(english:"Viralator CGI Script Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow arbitrary
code execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"The CGI 'viralator.cgi' is installed. Some versions of this 
CGI are don't check properly the user input and allow anyone 
to execute arbitrary commands with the privileges of the web 
server.

** No flaw was tested. Your script might be a safe version." );
 script_set_attribute(attribute:"solution", value:
"Upgrade this script to version 0.9pre2 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/viralator.cgi");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

if (is_cgi_installed3(port: port, item:"/viralator.cgi")) 
  security_hole(port);

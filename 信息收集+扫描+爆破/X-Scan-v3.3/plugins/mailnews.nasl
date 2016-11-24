#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10641);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0271");
 script_bugtraq_id(2391);
 script_xref(name:"OSVDB", value:"530");
 
 script_name(english:"MAILNEWS mailnews.cgi Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of mailnews.cgi");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a command execution\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "mailnews.cgi is being hosted on the remote web server.  Input to the\n",
     "'address' parameter is not properly sanitized.  A remote attacker\n",
     "could exploit this to execute arbitrary commands with the privileges\n",
     "of the web server.\n\n",
     "Please note Nessus only checked for the presence of this CGI, and did\n",
     "not attempt to exploit it, so this may be a false positive."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2001-02/0347.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove this CGI from the web server."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed3(item:"mailnews.cgi", port:port);
if(res)
 security_hole(port);

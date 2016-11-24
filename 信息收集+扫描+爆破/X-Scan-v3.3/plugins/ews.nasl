#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10064);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0279");
 script_bugtraq_id(2248);
 script_xref(name:"OSVDB", value:"55");

 script_name(english:"Excite for Web Server architext_query.pl Shell Metacharacter Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/ews");

 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has an arbitrary\n",
     "command execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "Excite for Webservers is installed. This CGI has a well-known\n",
     "security flaw that lets a remote attacker execute arbitrary\n",
     "commands with the privileges of the web server.\n\n",
     "Versions newer than 1.1. are patched."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1997_4/0502.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"If you are running version 1.1 or older, upgrade it."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( report_paranoia < 2 ) exit(0);

port = get_http_port(default:80);

res = is_cgi_installed3(item:"ews/ews/architext_query.pl", port:port);
if(res)security_hole(port);


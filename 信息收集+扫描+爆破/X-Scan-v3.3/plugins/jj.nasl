#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10131);
 script_version ("$Revision: 1.26 $");
 script_cve_id("CVE-1999-0260");
 script_bugtraq_id(2002);
 script_xref(name:"OSVDB", value:"105");

 script_name(english:"Multiple Vendor jj CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/jj");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"A CGI on the remote web server has a command execution vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The 'jj' CGI is installed. This CGI has a well-known security flaw\n",
     "that lets a remote attacker execute arbitrary commands with the\n",
     "privileges of the web server.\n\n",
     "Please note that Nessus only checked for the existence of this CGI,\n",
     "and did not attempt to exploit it."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1996_4/0464.html"
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

res = is_cgi_installed3(item:"jj", port:port);
if(res)security_hole(port);


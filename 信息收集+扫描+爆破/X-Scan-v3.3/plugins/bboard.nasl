#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if(description)
{
 script_id(10507);
 script_bugtraq_id(1459);
 script_version ("$Revision: 1.17 $");
 script_cve_id("CVE-2000-0629");
 script_xref(name:"OSVDB", value:"406");

 script_name(english:"Sun Java Web Server bboard Servlet Command Execution");
 script_summary(english:"Checks for the presence of /servlet/sunexamples.BBoardServlet");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application running on the remote host has an arbitrary command\n",
     "execution vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The 'bboard' servlet is installed in /servlet/sunexamples.BBoardServlet.\n",
     "This servlet comes with default installations of Sun Java Web Server\n",
     "and has a well-known security flaw that lets anyone execute arbitrary\n",
     "commands with the privileges of the web server."
   )
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Remove the affected servlet."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
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
res = is_cgi_installed3(item:"/servlet/nessus." + rand(), port:port);
if ( res ) exit(0);

res = is_cgi_installed3(item:"/servlet/sunexamples.BBoardServlet", port:port);
if( res ) security_hole(port);


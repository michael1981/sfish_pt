#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11465);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-1999-1180");
 script_xref(name:"OSVDB", value:"12962");
 script_xref(name:"OSVDB", value:"12963");

 script_name(english:"O'Reilly WebSite Pro args.bat Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-dos/args.bat");

 script_set_attribute(attribute:"synopsis", value:
"The remote website is susceptible to a remote command execution
attack.");
 script_set_attribute(attribute:"description", value:
"The CGI 'args.bat' (and/or 'args.cmd') is installed. This CGI has
a well known security flaw that lets an attacker upload arbitrary
files on the remote web server." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0738.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

res = is_cgi_installed3(item:"/cgi-dos/args.bat", port:port);
if (isnull(res)) exit (0);
if (res) { security_warning(port); exit(0); }

res = is_cgi_installed3(item:"/cgi-dos/args.cmd", port:port);

if (isnull(res)) exit (0);
if (res) { security_warning(port); exit(0); }

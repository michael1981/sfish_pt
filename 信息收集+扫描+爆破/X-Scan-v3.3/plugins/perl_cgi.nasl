#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10173);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-1999-0509");
 script_xref(name:"OSVDB", value:"200");

 script_name(english:"Web Server /cgi-bin Perl Interpreter Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary commands on the remote
system." );
 script_set_attribute(attribute:"description", value:
"The 'Perl' CGI is installed and can be launched as a CGI. 
This is equivalent to giving a free shell to an attacker, 
with the http server privileges (usually root or nobody)." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();
 
 script_summary(english:"checks for the presence of /cgi-bin/perl");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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

if ( report_paranoia < 2 ) exit(1, "report_paranoia is not set to paranoid.");

port = get_http_port(default:80);
if (is_cgi_installed3(item:"perl?-v", port:port) || 
    is_cgi_installed3(item:"perl.exe?-v", port:port))
  security_hole(port);

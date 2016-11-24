#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

# Changes by Tenable:
# - Revised plugin title (4/24/009)


include("compat.inc");

if(description)
{
 script_id(10188);
 script_version ("$Revision: 1.18 $");
 script_xref(name:"OSVDB", value:"11666");

 script_name(english:"Multiple Web Server printenv CGI Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"An installed CGI leaks sensitive information." );
 script_set_attribute(attribute:"description", value:
"The 'printenv' CGI is installed.
printenv normally returns all environment variables.

This gives an attacker valuable information about the
configuration of your web server." );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Checks for the presence of /cgi-bin/printenv");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Hendrik Scholz");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
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

cgi = "printenv";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_warning(port);


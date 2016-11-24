#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/2/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(10417);
 script_version ("$Revision: 1.17 $");
 script_xref(name:"OSVDB", value:"319");

 script_name(english:"Sambar Server /cgi-bin/mailit.pl Arbitrary Mail Relay");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that allows unauthorized mail
relaying." );
 script_set_attribute(attribute:"description", value:
"The Sambar webserver is running and the 'mailit.pl' cgi is 
installed. This CGI takes a POST request from any host and sends a 
mail to a supplied address." );
 script_set_attribute(attribute:"solution", value:
"remove it from /cgi-bin." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of /cgi-bin/mailit");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Hendrik Scholz");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/sambar");
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

cgi = "/cgi-bin/mailit.pl";
res = is_cgi_installed_ka(port:port, item:cgi);
if(res)security_warning(port);

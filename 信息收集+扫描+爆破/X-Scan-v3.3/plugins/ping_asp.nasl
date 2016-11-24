#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added CAN.  Added link to the Bugtraq message archive


include("compat.inc");

if(description)
{
 script_id(10968);
 script_version ("$Revision: 1.13 $");
 script_xref(name:"OSVDB", value:"53949");
 
 script_name(english:"ping.asp CGI Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"A CGI could be used to launch denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The 'ping.asp' CGI is installed. Some versions allows a cracker to 
launch a ping flood against your machine or another by entering
'127.0.0.1 -l 65000 -t' in the Address field." );
 script_set_attribute(attribute:"solution", value:
"Remove it." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/ntbugtraq/2002-q2/0125.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C" );

script_end_attributes();

 
 script_summary(english:"Checks for the presence of ping.asp");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl", "webmirror.nasl");
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
if ( ! can_host_asp(port:port) ) exit(0);

if (is_cgi_installed3(port:port, item:"ping.asp"))
{
 security_hole(port);
 exit(0);
}

if (is_cgi_installed3(port:port, item:"/ping.asp"))
{
 security_hole(port);
 exit(0);
}

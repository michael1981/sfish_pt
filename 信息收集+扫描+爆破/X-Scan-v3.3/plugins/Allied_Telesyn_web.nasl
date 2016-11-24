#
#
# This script was written by Charles Thier <cthier@thethiers.net>
# This script was based off of Renaud Deraison's script 
# 11522 Linksys Router default password script.
# GPLv2
#


include("compat.inc");

if(description)
{
    script_id(18413);
    script_version("$Revision: 1.8 $");
    script_cve_id("CVE-1999-0508");
    script_name(english:"Allied Telesyn Router/Switch Web Interface Default Password");
    script_summary(english:"Logs into Allied Telesyn routers and switches Web interface with default password");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an account with a default password set." );
 script_set_attribute(attribute:"description", value:
"The Allied Telesyn Router/Switch has the default password set.

The attacker could use this default password to gain remote access to
your switch or router. This password could also be potentially used to
gain other sensitive information about your network from the device." );
 script_set_attribute(attribute:"solution", value:
"Connect to this Router/Switch and set a strong password." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2005-2009 Charles Thier");
   script_family(english:"Misc.");
   script_dependencies("http_version.nasl");
   script_require_ports("Services/www", 80);

   exit(0);
}


#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner (port:port);
if (!banner || ("Server: ATR-HTTP-Server" >!< banner))
  exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ( egrep ( pattern:"^HTTP/.* 401 .*", string:res ) )
{
 req -= string("\r\n\r\n");
#  Credentials manager:friend
 req += string("\r\nAuthorization: Basic bWFuYWdlcjpmcmllbmQ=\r\n\r\n");
 res = http_keepalive_send_recv(port:port, data:req);
 if (res == NULL ) exit(0);
 if ( egrep ( pattern:"^HTTP/.* 200 .*", string:res) )
	security_hole(port);
}


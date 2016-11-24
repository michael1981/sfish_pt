#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
# This script is released under the GNU GPLv2

# Changes by Tenable:
# - Revised plugin title, updated solution (4/28/09)


include("compat.inc");

if(description)
{
 script_id(14225);
 script_version ("$Revision: 1.17 $");

 script_bugtraq_id(10847);
 script_xref(name:"OSVDB", value:"8229");

 script_name(english:"BreakCalendar < 1.3 XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI that is affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running BreakCalendar, a web-based
calendar. 

The remote version of this software is vulnerable to a cross-site
scripting attack that may allow an attacker to use the remote host to
perform attacks against third party users." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.3" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N" );

script_end_attributes();

 
 script_summary(english:"Checks for BreakCalendar version");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))
	exit(0);

function check(url)
{
	local_var r, req;
	req = http_get(item:string(url, "/breakcal/calendar.cgi"),
 		port:port);
	r = http_keepalive_send_recv(port:port, data:req);
	if ( r == NULL ) 
		exit(0);
	#Powered by breakcal v1.65pr1
	if(egrep(pattern:"Powered by breakcal v1\.[0-4][0-9]*[^0-9]", string:r))
 	{
 		security_warning(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
		exit(0);
	}
 
}

foreach dir (cgi_dirs())
{
 	check(url:dir);
}

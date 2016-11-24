#
# (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
 script_id(16071);
 script_version ("$Revision: 1.11 $");

 script_cve_id("CVE-2004-1423");
 script_bugtraq_id(12127, 20657);
 script_xref(name:"OSVDB", value:"12700");
 script_xref(name:"OSVDB", value:"12701");

 script_name(english:"PHP-Calendar Multiple Script phpc_root_path Parameter Remote File Inclusion");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
remote file include vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running PHP-Calendar, a web-based calendar
written in PHP. 

The remote version of this software is vulnerable to a file inclusion
flaw which may allow an attacker to execute arbitrary PHP commands on
the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00060-12292004" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2004-12/0441.html" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=296020&group_id=46800" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PHP-Calendar version 0.10.1 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Determines if PHP-Calendar can include third-party files");
 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2008 Tenable Network Security");

 script_dependencies("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach d (cgi_dirs())
{
 url = string(d, "/includes/calendar.php?phpc_root_path=http://xxxx./");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = r[2];
 if ( "http://xxxx./includes/html.php" >< buf )
 {
  security_hole(port);
  exit(0);
 }
}

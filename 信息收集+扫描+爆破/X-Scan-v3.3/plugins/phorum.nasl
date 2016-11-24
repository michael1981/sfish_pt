#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10593);
 script_version ("$Revision: 1.22 $");
 script_bugtraq_id(1997);
 script_xref(name:"OSVDB", value:"53866");

 script_name(english:"Phorum common.php ForumLang Parameter Traversal Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that suffers from an
information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The version of Phorum installed on the remote host lets an attacker
read arbitrary files on the affected host with the privileges of the
http daemon because it fails to filter input to the 'ForumLang'
parameter of the 'support/common.php' script of directory traversal
sequences." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-11/0338.html" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=phorum-announce&m=97500921223488&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Phorum 3.2.8 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );
script_end_attributes();

 
 script_summary(english:"Checks for the presence of Phorum's common.php");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phorum_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);


function check(prefix)
{
  local_var buf, r;
  global_var port;

  r = http_send_recv3(method:"GET", port: port,
      item:string(prefix, "?f=0&ForumLang=../../../../../../../etc/passwd"));
  if (isnull(r)) exit(0);
  buf = strcat(r[0], r[1], '\r\n', r[2]);  
  if(egrep(pattern:".*root:.*:0:[01]:.*", string:buf)) {
  	security_warning(port);
	exit(0);
	}
}

# Test an install.
install = get_kb_item(string("www/", port, "/phorum"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  check(prefix:string(dir, "/support/common.php"));
  check(prefix:string(dir, "/common.php"));
}

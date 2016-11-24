#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Positive Technologies - www.maxpatrol.com
# This script is released under the GNU GPLv2
#

include("compat.inc");

if(description)
{
  script_id(15556);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2004-2177", "CVE-2004-2178");
  script_bugtraq_id(11428);
  script_xref(name:"OSVDB", value:"10766");
  script_xref(name:"OSVDB", value:"10767");

  script_name(english:"DevoyBB Multiple Remote Vulnerabilities (SQLi, XSS)");
  script_summary(english:"Checks DevoyBB version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running DevoyBB, a web-based forum written in PHP. 

The installed version is vulnerable to XSS and SQL injection attacks. 
A malicious user can access a user's cookies, including authentication
cookies, and inject SQL commands to be executed on the underlying
database.");
  script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"plugin_publication_date", value:
"2004/10/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

function check(req)
{
  local_var buf, r;
  buf = http_get(item:string(req,"/index.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if(isnull(r))exit(0);

  if(egrep(pattern:" - Powered by DevoyBB</title>.*Powered by <a href=.http://www\.devoybb\.com.*><strong>DevoyBB (0\..*|1\.0\.0)</strong>", string:r))
  {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
  }
}

foreach dir (cgi_dirs()) check(req:dir);

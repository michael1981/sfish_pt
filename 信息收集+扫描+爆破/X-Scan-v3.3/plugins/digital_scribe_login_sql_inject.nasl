#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: retrogod at aliceposta.it
# This script is released under the GNU GPLv2
#

include("compat.inc");

if(description)
{
  script_id(19770);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2005-2987");
  script_bugtraq_id(14843);
  script_xref(name:"OSVDB", value:"19460");

  script_name(english:"Digital Scribe login.php SQL Injection");
  script_summary(english:"Checks for SQL injection flaw in Digital Scribe");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to a
SQL injection attack.");
 script_set_attribute(attribute:"description", value:
"The remote web server hosts Digital Scribe, a student-teacher set of
scripts written in PHP. 

The version of Digital Scribe installed on the remote host is prone to
a SQL injection attack through the 'login.php' script.  A malicious
user may be able to exploit this issue to manipulate database queries
to, say, bypass authentication.");
 script_set_attribute(attribute:"see_also", value:
"http://retrogod.altervista.org/dscribe14.html");
 script_set_attribute(attribute:"see_also", value:
"http://archives.neohapsis.com/archives/bugtraq/2005-09/0147.html");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"vuln_publication_date", value:
"2005/09/15");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2005/09/21");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
  script_family(english:"CGI abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("misc_func.inc");

function check(req)
{
  local_var buf, r;
  global_var port;

  buf = http_get(item:string(req,"/login.php"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( isnull(r) )exit(0);
  if (("<TITLE>Login Page</TITLE>" >< r) && (egrep(pattern:"www\.digital-scribe\.org>Digital Scribe v\.1\.[0-4]$</A>", string:r)))
  {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
  }
}

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port))exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/DigitalScribe", "/scribe", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  check(req:dir);
}

#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# 
# Ref: Positive Technologies - www.maxpatrol.com
# This script is released under the GNU GPLv2
#


include("compat.inc");

if(description)
{
  script_id(15557);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2004-2180", "CVE-2004-2181");
  script_bugtraq_id(11429);
  script_xref(name:"OSVDB", value:"10771");
  script_xref(name:"OSVDB", value:"10772");
  script_xref(name:"OSVDB", value:"16543");
  script_xref(name:"OSVDB", value:"19189");
  script_xref(name:"OSVDB", value:"19190");
  script_xref(name:"OSVDB", value:"19191");
  script_xref(name:"OSVDB", value:"19192");
  script_xref(name:"OSVDB", value:"19193");
  script_xref(name:"OSVDB", value:"19194");
  script_xref(name:"OSVDB", value:"19195");

  script_name(english:"WowBB <= 1.61 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running WowBB, a web-based forum written in PHP. 

According to its version, the remote installation of WowBB is 1.61 or
older.  Such versions are vulnerable to cross-site scripting and SQL
injection attacks.  A malicious user can steal users' cookies,
including authentication cookies, and manipulate SQL queries." );
 script_set_attribute(attribute:"see_also", value:"http://www.maxpatrol.com/advdetails.asp?id=7" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();


  script_summary(english:"Checks WowBB version");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if(!can_host_php(port:port))exit(0);

function check(req)
{
  local_var r;

  r = http_get_cache(item:string(req, "/index.php"), port:port);
  if( r == NULL )exit(0);
  if(egrep(pattern:"WowBB Forums</TITLE>.*TITLE=.WowBB Forum Software.*>WowBB (0\..*|1\.([0-5][0-9]|60|61))</A>", string:r))
  {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
  }
}

if (thorough_tests) dirs = list_uniq(make_list("/forum", "/forums", "/board", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) check(req:dir);

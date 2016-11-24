#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (4/20/009)


include("compat.inc");

if(description)
{
 script_id(11730);
 script_version ("$Revision: 1.12 $");
 script_cve_id("CVE-2001-0922");
 script_bugtraq_id(3583); 
 script_xref(name:"OSVDB", value:"13991");
 
 script_name(english:"Netdynamics ndcgi.exe Previous User Session Replay");

 script_set_attribute(attribute:"synopsis", value:
"User sessions may be hijacked on the remote host." );
 script_set_attribute(attribute:"description", value:
"The file ndcgi.exe exists on this webserver.  
Some versions of this file are vulnerable to remote exploit.

*** As Nessus solely relied on the existence of the ndcgi.exe file, 
*** this might be a false positive" );
 script_set_attribute(attribute:"solution", value:
"Remove it from /cgi-bin." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=100681274915525&w=2" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the ndcgi.exe file");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2009 John Lampe");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

flag = 0;
directory = "";

no404 = get_kb_item("www/no404/" + port );

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/ndcgi.exe"), port:port)) {
   	if(no404 && is_cgi_installed_ka(item:string(dir, "/nessus" + rand() + ".exe"), port:port)) exit(0);
  	flag = 1;
  	directory = dir;
  	break;
  }
}
 
if (flag) security_hole(port);

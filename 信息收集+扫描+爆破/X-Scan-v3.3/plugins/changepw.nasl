#
# This script was written by John Lampe...j_lampe@bellsouth.net 
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(11723);
 script_bugtraq_id(1256);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0401");
 script_xref(name:"OSVDB", value:"11440");
 script_xref(name:"OSVDB", value:"11441");
 
 script_name(english:"PDGSoft Shopping Cart Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The executables 'redirect.exe' and/or 'changepw.exe' exist on this 
webserver. Some versions of these files are vulnerable to remote 
exploit.

An attacker can use this hole to gain access to confidential data
or escalate their privileges on the web server.

*** As Nessus solely relied on the existence of the redirect.exe or 
*** changepw.exe files, this might be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=95928319715983&w=2" );
 script_set_attribute(attribute:"solution", value:
"The vendor has released a patch that addresses this issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Checks for PDGSoft Shopping cart executables";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO); # mixed
 
 script_copyright(english:"This script is Copyright (C) 2003-2009 John Lampe");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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

if (get_kb_item("www/" + port + "/no404") ) exit(0);

flag = 0;
directory = "";

foreach dir (cgi_dirs()) {
   if(is_cgi_installed_ka(item:string(dir, "/changepw.exe"), port:port)) {
  	flag = 1;
  	directory = dir;
  	break;
   } 
   if(is_cgi_installed_ka(item:string(dir, "/redirect.exe"), port:port)) {
	flag = 1;
        directory = dir;
        break;
   }
}
 
if (flag) security_hole(port);

#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# ref: Morinex Eneco <m0r1n3x@gmail.com>
# This script is released under the GNU GPLv2
#

include("compat.inc");

# Changes by Tenable:
# - Revised plugin title (4/9/2009)

if(description)
{
 script_id(18260);
 script_version ("$Revision: 1.9 $");

 script_cve_id("CVE-2005-1614", "CVE-2005-1615", "CVE-2005-1616");
 script_bugtraq_id(13621, 13622);
 script_xref(name:"OSVDB", value:"16771");
 script_xref(name:"OSVDB", value:"16772");
 script_xref(name:"OSVDB", value:"16773");
 
 script_name(english:"Ultimate PHP Board < 1.9.7 viewforum.php Multiple Vulnerabilities");

  script_set_attribute(
    attribute:"synopsis",
    value:"A web application on the remote host has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Ultimate PHP Board (UPB).  The remote
version of this software is vulnerable to cross-site scripting
attacks, and SQL injection flaws.

Using a specially crafted URL, an attacker may execute arbitrary
commands against the remote SQL database or use the remote server to
set up a cross site scripting attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://archives.neohapsis.com/archives/bugtraq/2005-05/0165.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to UPB 1.9.7 or later."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
  );
  script_end_attributes();
 
 script_summary(english:"Checks for UPB");
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


foreach d ( cgi_dirs() )
{
 req = http_get(item:string(d, "/index.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(egrep(pattern:"Powered by UPB Version :.* (0\.|1\.([0-8][^0-9]|9[^0-9]|9\.[1-6][^0-9]))", string:res))
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	exit(0);
 }
}

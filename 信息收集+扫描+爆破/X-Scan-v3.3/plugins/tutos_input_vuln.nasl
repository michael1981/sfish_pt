#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: Francois SORIN <francois.sorin@kereval.com>
#
#  This script is released under the GNU GPL v2

# Changes by Tenable:
# - Revised plugin title (4/9/2009)

include("compat.inc");

if(description)
{
 script_id(14793);
 script_version("$Revision: 1.8 $");
 script_bugtraq_id(10129);
 script_xref(name:"OSVDB", value:"5326");
 script_xref(name:"OSVDB", value:"5327");
 script_xref(name:"OSVDB", value:"5328");
 script_xref(name:"OSVDB", value:"5329");

 script_name(english:"TUTOS < 1.1.20040412 Multiple Input Validation Issues");

 script_set_attribute(
   attribute:"synopsis",
   value:"A web application on the remote host has multiple vulnerabilities."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host is running Tutos, an open-source team organization
software package written in PHP.

According to its banner, the remote version of this software is
vulnerable to multiple input validation flaws which may allow an
authenticated user to perform a cross site scripting attack, path
disclosure attack or a SQL injection against the remote service."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to Tutos-1.1.20040412 or later."
 );
 script_set_attribute(
   attribute:"cvss_vector",
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();
 
 script_summary(english:"Checks the version of Tutos");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if ( ! can_host_php(port:port) ) exit(0);


foreach dir (cgi_dirs()) 
 {
  req = http_get(item:dir + "/php/mytutos.php", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) exit(0);
  if ( '"GENERATOR" content="TUTOS' >< res &&
       egrep(pattern:".*GENERATOR.*TUTOS (0\..*|1\.(0\.|1\.(2003|20040[1-3]|2004040[0-9]|2004041[01])))", string:res) )
	{
	 security_hole(port);
	 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	 exit(0);
	}
 }


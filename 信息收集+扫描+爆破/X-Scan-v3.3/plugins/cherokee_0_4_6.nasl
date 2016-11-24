#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from Tenable Network Security
#
#  Ref: <vnull@pcnet.com.pl>
#
#  This script is released under the GNU GPL v2
#

# Changes by Tenable:
# - Revised plugin title (4/6/2009)


include("compat.inc");

if(description)
{
 script_id(15620);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2003-1198");
 script_bugtraq_id(9345);
 script_xref(name:"OSVDB", value:"3306");

 script_name(english:"Cherokee Web Server Malformed POST Request Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial-of-service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Cherokee - a fast and tiny web server.

The remote version of this software is affected by a remote denial of
service vulnerability when handling a specially-crafted HTTP 'POST'
request. 

An attacker may exploit this flaw to disable this service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?76d15ca6" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Cherokee 0.4.7 or newer as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for version of Cherokee");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.[0-6])[^0-9]", string:serv))
 {
   security_warning(port);
 }

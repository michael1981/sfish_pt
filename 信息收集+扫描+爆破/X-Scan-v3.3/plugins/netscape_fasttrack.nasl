#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10156);
 script_version ("$Revision: 1.27 $");
 script_cve_id("CVE-1999-0239");
 script_bugtraq_id(481);
 script_xref(name:"OSVDB", value:"122");

 script_name(english:"Netscape FastTrack get Command Forced Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to an information disclosure
attack." );
 script_set_attribute(attribute:"description", value:
"When the remote web server is issued a request with a lower-case
'get', it will return a directory listing even if a default page such
as index.html is present. 
		
For example :
		get / HTTP/1.0

will return a listing of the root directory. 

This allows an attacker to gain valuable information about the
directory structure of the remote host and could reveal the presence
of files that are not intended to be visible." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your server to the latest version." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"'get / ' gives a directory listing");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/netscape-fasttrack");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

bad = "<title>index of /</title>";



function check(pattern, port)
{
 local_var req, res;
 
 
 req = http_get(item:"/", port:port);
 req = str_replace(string:req, find:pattern, replace:"get", count:1);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 res = tolower(res);
 if(bad >< res){
 	security_warning(port);
	exit(0);
  }
}


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

req = http_get(item:"/", port:port);
res = http_keepalive_send_recv(port:port, data:req);
if( res == NULL ) exit(0);

res = tolower(res);
if(bad >< res) exit(0);

# See www.securityfocus.com/bid/481/exploit

check(pattern:"GET", port:port);
check(pattern:"GET ", port:port);


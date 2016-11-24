#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11504);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2002-1629");
 script_bugtraq_id(7203);
 script_xref(name:"OSVDB", value:"19107");
 
 script_name(english:"MultiTech Proxy Server Default Null Password");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Proxy server uses a default password." );
 script_set_attribute(attribute:"description", value:
"The remote MultiTech Proxy Server has no password set for the 
'supervisor' account.

An attacker may log in the remote host and reconfigure it 
easily." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2002-12/0105.html" );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for the 'supervisor' account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Attempts to log into the remote web server");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);



req = http_get(item:"/std.html", port:port);
auth = egrep(pattern:"^Authorization", string:req);
if(auth) req = req - auth;
 
res = http_keepalive_send_recv(port:port, data:req);
if(res == NULL) exit(0);
 
if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 40[13] .*", string:res))
 { 
  idx = stridx(req, string("\r\n\r\n"));
  req = insstr(req, string("\r\nAuthorization: Basic c3VwZXJ2aXNvcjo=\r\n\r\n"), idx);
  
  res = http_keepalive_send_recv(port:port, data:req);
  if(res == NULL) exit(0);
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res))
  {
   security_hole(port);
   exit(0);
  }
 }

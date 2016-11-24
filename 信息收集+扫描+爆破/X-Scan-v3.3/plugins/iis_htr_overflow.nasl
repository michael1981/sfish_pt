#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID


include("compat.inc");

if(description)
{
 script_id(11028);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2002-0364", "CVE-2002-0071");
 script_bugtraq_id(4855, 5003);
 script_xref(name:"OSVDB", value:"5316");
 script_xref(name:"OSVDB", value:"3325");
 script_xref(name:"IAVA", value:"2002-A-0002"); 
 script_xref(name:"IAVA", value:"2002-t-0013");

 script_name(english:"Microsoft IIS .HTR Filter Multiple Overflows (MS02-028)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server is vulnerable to a buffer overflow in the .HTR
filter.

An attacker may use this flaw to execute arbitrary code on
this host (although the exploitation of this flaw is considered
as being difficult)." );
 script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/technet/security/bulletin/MS02-028.mspx" );
 script_set_attribute(attribute:"solution", value:
"To unmap the .HTR extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
 5.Remove the reference to .htr from the list.

See MS bulletin MS02-028 for a patch" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Tests for IIS .htr ISAPI filter");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

sig = get_http_banner(port: port);
if ("IIS" >!< sig ) exit(0);

d = '20\r\n'
  + crap(32) + 'r\n'
  + '0\r\n\r\n';
r = http_mk_post_req(item:"/NULL.htr", 
  add_headers: make_array("Transfer-Encoding", "chunked"),
  data: d);

soc = http_open_socket(port);
if (! soc) exit(1, "port "+port+ " is closed or filtered");

req = http_mk_buffer_from_req(req: r);
send(socket:soc, data:req);
r = http_recv_headers3(socket:soc);
if (r =~ "^HTTP/1.[01] 100 Continue")
{
  r2 = http_recv_body(socket:soc, length:0, headers:r);
  if (! r2) security_hole(port);
}
http_close_socket(soc);

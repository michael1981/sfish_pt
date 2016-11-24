#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#

include("compat.inc");

if(description)
{
 script_id(10554);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2000-1181");
 script_bugtraq_id(1957);
 script_xref(name:"OSVDB", value:"453");
 
 script_name(english: "RealServer /admin/includes/ Remote Memory Content Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote Real Server discloses the content of its memory when issued 
the request :

	GET /admin/includes/
	
This information may be used by an attacker to obtain administrative 
control on this server, or to gain more knowledge about it." );
 script_set_attribute(attribute:"solution", value:
"Install RealServer G2 7.0update2" );
 script_set_attribute(attribute:"see_also", value:"http://service.real.com/help/faq/security/memory.html" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"dumps the memory of a real g2 server");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports(7070, "Services/realserver");
 script_dependencies("find_service1.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}


include("http_func.inc");
include('global_settings.inc');

if ( ! thorough_tests )exit(0);

port7070 = get_kb_item("Services/realserver");
if(!port7070)port7070 = 7070;

if(get_port_state(port7070))
{
  if ( ! get_http_banner(port:port7070) ) exit(0);

  req = http_get(item:"/admin/includes", port:port7070);
  soc = http_open_socket(port7070);
  if(soc)
  {
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:4096);
   http_close_socket(soc);
   if(" 404 " >< r)
   {
    req = http_get(item:"/admin/includes/", port:port7070);
    soc = http_open_socket(port7070);
    send(socket:soc, data:req);
    r = recv_line(socket:soc, length:4096);
    headers = http_recv_headers2(socket:soc);
    body = http_recv_body(socket:soc, headers:headers, length:0);
    if("application/octet-stream" >!< headers) exit(0);
    http_close_socket(soc);
    if(strlen(body) > 2)
      security_warning(port7070);
   }
  }
}

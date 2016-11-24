#
# (C) Tenable Network Security, Inc.
#

#
# Should also cover http://archives.neohapsis.com/archives/vulnwatch/2003-q2/0082.html
#


include("compat.inc");

if(description)
{
 script_id(10578);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2001-0029");
 script_bugtraq_id(2099);
 script_xref(name:"OSVDB", value:"476");
 
 script_name(english:"oops WWW Proxy Server Reverse DNS Response Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a buffer overflow 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote server appears to be running ooops WWW proxy 
server version 1.4.6 or older. Such versions are reportedly
affected by a buffer overflow vulnerability. A remote 
attacker might exploit this vulnerability to crash the 
server or execute arbitrary commands on the remote system." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-12/0158.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Overflows oops");
 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/http_proxy", 3128);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if(report_paranoia < 2) exit(1,"report_paranoia < 2");

port = get_kb_item("Services/http_proxy");
if(!port) port = 3128;

if(http_is_dead(port: port)) exit(0);

res = http_send_recv3(method:"GET", item:string("http://", crap(12)), port:port);
if(isnull(res)) exit(1,"Null response to crap request.");

req = string("http://", crap(1200));
res = http_send_recv3(method:"GET", item:req, port:port);

if(isnull(res))
{
  for(i = 0; i < 3 ; i++)
  {
    sleep(1);
    res = http_send_recv3(method:"GET", item:req, port:port);
    if(!isnull(res))
     exit(0);
  }
  security_hole(port);
}

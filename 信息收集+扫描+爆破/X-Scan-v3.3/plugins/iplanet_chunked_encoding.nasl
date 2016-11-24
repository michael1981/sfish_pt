#
# (C) Tenable Network Security, Inc.
#

# Tested against iPlanet 4.1SP10 (vulnerable), 6.0SP4 (not vulnerable)
# and 4.0 (not vulnerable)
#
# Script audit and contributions from Carmichael Security 
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#


include("compat.inc");

if(description)
{
 script_id(11068);
 script_version("$Revision: 1.17 $");
 script_cve_id("CVE-2002-0845");
 script_bugtraq_id(5433);
 
 script_name(english:"iPlanet Chunked Encoding Processing Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote applicaiton server is affected by a buffer overflow 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"This host is running the Sun One/iPlanet web server 4.1 or 6.0.  This 
web server contains an unchecked buffer in the 'Chunked Encoding' 
processing routines.  By issuing a malformed request to the web server, 
a potential intruder can 'POST' extraneous data and cause the web 
server process to execute arbitrary code.  This allows the potential 
intruder to gain access to this host." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=102890933623192&w=2" );
 script_set_attribute(attribute:"solution", value:
"The vendor has released Sun ONE web server 4.1 service pack 11 and 6.0
service pack 4 to fix this issue." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_summary(english:"Checks for the behavior of iPlanet");
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_keys("www/iplanet");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{	
 req1 = string(		
		"4\r\n",
		"XXXX\r\n",
		"7FFFFFFF\r\n",
		crap(50), "\r\n\r\n");

  req = string("POST /foo.html HTTP/1.1\r\n",
 		"Host: ", get_host_name(), "\r\n",
		"Transfer-Encoding: chunked\r\n",
		"Content-Length: ", strlen(req1), "\r\n\r\n", req1);
		
  soc = open_sock_tcp(port);
  if(soc)
  {
   send(socket:soc, data:http_get(item:"/", port:port));
   init = http_recv_headers2(socket:soc);
   close(soc);

   
 
   soc = open_sock_tcp(port);
   
   #
   # We need to make sure this is iPlanet, or else we will
   # false postive against Apache.
   #
   if(egrep(pattern:"^HTTP/1\.[0-1] [0-9]* .*", string:init) &&
      (egrep(pattern:"^Server: .*Netscape-Enterprise", string:init)))
   {
    send(socket:soc, data:req);
    r = http_recv(socket:soc);
    close(soc);
    # Vulnerable versions wait for the data to arrive,
    # Patched versions will spew an error 411.
    if(!r)security_hole(port);
   }
  }
 }

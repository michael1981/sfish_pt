#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10153);
 script_version ("$Revision: 1.30 $");
 script_cve_id("CVE-1999-0269");
 script_bugtraq_id(7621);
 script_xref(name:"OSVDB", value:"119");

 script_name(english:"Netscape Server ?PageServices Request Forced Directory Listing");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information  
disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"Requesting an URL with '?PageServices' appended to it makes 
some Netscape servers dump the listing of the page directory, 
thus revealing potentially sensitive files to an attacker." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your Netscape server or turn off indexing." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

 script_summary(english:"Make a request like http://www.example.com/?PageServices");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iplanet");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(get_port_state(port))
{
  seek = "<title>index of /</title>";
  data = http_get_cache(item:"/", port:port);
  data_low = tolower(data);
  if(seek >< data_low)exit(0);
  
  soc = http_open_socket(port);
  if ( ! soc ) exit(0);
  buffer = http_get(item:"/?PageServices", port:port);
  send(socket:soc, data:buffer);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  data_low = tolower(data);
  
  if(seek >< data_low) security_warning(port);
}

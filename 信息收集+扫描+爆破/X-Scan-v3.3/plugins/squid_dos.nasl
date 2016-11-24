#
# This script was written by Adam Baldwin <adamb@amerion.net>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (6/16/09)
# - Standardized product name in title (6/25/09)
# - Change plugin family (7/6/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(10768);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2001-0843");
 script_bugtraq_id(3354);
 script_xref(name:"OSVDB", value:"639");

 script_name(english:"Squid mkdir-only PUT Request Remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial
of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"A problem exists in the way the remote Squid proxy server handles a 
special 'mkdir-only' PUT request, and causes denial of service to the 
proxy server.

An attacker may use this flaw to prevent your LAN users from accessing
the web." );
 script_set_attribute(attribute:"solution", value:
"Apply the vendor released patch, for squid it is located here: 
www.squid-cache.org.  You can also protect yourself by enabling access 
lists on your proxy.

*** Note that Nessus solely relied on the version number of the remote
*** proxy to issue this warning" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );


script_end_attributes();

 script_summary(english:"Determines via ver. if a proxy server is DoSable");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Firewalls");
 script_copyright(english:"This script is Copyright (C) 2001-2009 Adam Baldwin");
 script_dependencies("find_service1.nasl", "proxy_use.nasl");
 script_require_ports("Services/http_proxy", 8080, 3128);
 exit(0);
}

#
# Code Starts Here
#

include("http_func.inc");

port = get_kb_item("Services/http_proxy");
if(!port)port = 3128;
if(!get_port_state(port))port = 8080;


if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  sData = http_get(item:"http://www.$$$$$", port:port);
  send(socket:soc, data:sData);
  data = http_recv(socket:soc);
  http_close_socket(soc);
  data = egrep(pattern: "^Server: ", string: data);

  if("Squid" >< data)
  {
   data = data - string("Server: Squid/");
   #See if it's a vulnerable version
   #CHECK VERSION 2.3
   if(("2.3" >< data) && ("STABLE2" >< data) ||
  	 		 ("STABLE3" >< data) ||
			 ("STABLE4" >< data) ||
			 ("STABLE5" >< data))
   {
    security_warning(port);
   }
   #CHECK VERSION 2.4
   if(("2.4" >< data) && ("STABLE1" >< data) || 
			 ("PRE-STABLE2" >< data) || 
			 ("PRE-STABLE" >< data) ||
			 ("DEVEL4" >< data) ||
			 ("DEVEL2" >< data))
   {
    security_warning(port);
   }
  }
 }
}

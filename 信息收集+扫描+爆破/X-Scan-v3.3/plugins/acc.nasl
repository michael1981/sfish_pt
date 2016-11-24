#
#
# This script was written by Sebastian Andersson <sa@hogia.net>
#

# Changes by Tenable:
# - french description, script id, cve id [RD]
# - changed family (9/6/09)

#
# See the Nessus Scripts License for details
#



include("compat.inc");

if(description)
{
 script_id(10351);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-1999-0383");
 script_bugtraq_id(183);
 script_xref(name:"OSVDB", value:"267");
 
 script_name(english:"ACC Tigris Access Terminal Configuration Disclosure");
 script_summary(english:"Checks for ACC SHOW command bug");

 script_set_attribute(attribute:"synopsis", value:
"The remote router is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote router is an ACC Tigris Terminal Server.  Some software
versions on this router will allow an attacker to run the SHOW command
without first providing authentication.  An attacker could exploit
this to read part of the router's configuration. 

In addition there is a 'public' account with a default password of
'public' which would allow an attacker to execute non-privileged
commands on the host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0023.html" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/1999_1/0032.html" );
 script_set_attribute(attribute:"solution", value:
"Add access entries to the server to allow access only from authorized
staff." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N" );

script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2009 Sebastian Andersson");
 script_family(english:"Misc.");
 script_dependencies("find_service1.nasl");
 script_require_ports("Services/telnet", 23);
 exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if(!port)port = 23;

banner = get_telnet_banner(port:port);
if ( ! banner || "Login:" >< banner ) exit(0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  first_line = telnet_negotiate(socket:soc);
  if("Login:" >< first_line) {
   req = string("\x15SHOW\r\n");
   send(socket:soc, data:req);
   r = recv_line(socket:soc, length:1024);
   r = recv_line(socket:soc, length:1024);
   if(("SET" >< r) ||
      ("ADD" >< r) ||
      ("RESET" >< r)) {
    security_warning(port);
    # cleanup the router...
    while(! ("RESET" >< r)) {
     if("Type 'Q' to quit" >< r) {
      send(socket:soc, data:"Q");
      close(soc);
      exit(0);
     }
     r = recv(socket:soc, length:1024);
    }
   }
  }
  close(soc);
 }
}

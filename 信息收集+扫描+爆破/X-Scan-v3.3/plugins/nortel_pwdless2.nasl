#
# This script was written by Victor Kirhenshtein <sauros@iname.com>
# Based on cisco_675.nasl by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/2/09)


include("compat.inc");

if(description)
{
   script_id(10529);
   script_version ("$Revision: 1.12 $");
   script_xref(name:"OSVDB", value:"428");

   script_name(english:"Nortel Networks Router Unpassworded Account (user Level)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is reachable without any password." );
 script_set_attribute(attribute:"description", value:
"The remote Nortel Networks (former Bay Networks) router has
no password for user account. 

An attacker could telnet to the router and reconfigure it to lock 
you out of it, and to prevent you to use your internet 
connection." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this router and set a password immediately." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();

   script_summary(english:"Logs into the remote Nortel Networks (Bay Networks) router");
   script_category(ACT_GATHER_INFO);
   script_copyright(english:"This script is Copyright (C) 2000-2009 Victor Kirhenshtein");
   script_family(english:"Misc.");
   script_require_ports(23);
   exit(0);
}

#
# The script code starts here
#
include('telnet_func.inc');
port = 23;
if(get_port_state(port))
{
   buf = get_telnet_banner(port:port);
   if ( ! buf  || "Bay Networks" >!< buf ) exit(0);
   soc = open_sock_tcp(port);
   if(soc)
   {
      buf = telnet_negotiate(socket:soc);
      if("Bay Networks" >< buf)
      {
         if ("Login:" >< buf)
         {
            data = string("User\r\n");
            send(socket:soc, data:data);
            buf2 = recv(socket:soc, length:1024);
            if("$" >< buf2) security_hole(port);
         }
      }
      close(soc);
   }
}

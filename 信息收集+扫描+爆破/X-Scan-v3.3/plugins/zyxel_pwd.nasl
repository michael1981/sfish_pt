#
#
# This script was written by Giovanni Fiaschi <giovaf@sysoft.it>
#
# See the Nessus Scripts License for details
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID.  
#
# Changes by Tenable:
# - Updated to use compat.inc (11/16/09)
# - Changed formatting and removed French (3/26/2009)
# - Revised title (12/22/2008)


include("compat.inc");

if(description)
{
   script_id(10714);
   script_cve_id("CVE-1999-0571");
   script_bugtraq_id(3161);
   script_xref(name:"OSVDB", value:"592");
   script_version ("$Revision: 1.23 $");
   
   name["english"] = "ZyXEL Router Default Telnet Password Present";
   script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a router with its default password set." );
 script_set_attribute(attribute:"description", value:
"The remote host is a ZyXEL router with a default password. An attacker could
telnet to it and reconfigure it to lock the owner out and prevent him from
using his Internet connection, or create a dial-in user to connect directly
to the LAN attached to it." );
 script_set_attribute(attribute:"solution", value:
"Telnet to this router and set a password immediately." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 
   summary["english"] = "Logs into the ZyXEL router";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english:"This script is Copyright (C) 2001-2009 Giovanni Fiaschi");
   script_family(english:"Misc.");
   script_require_ports(23);
 
   exit(0);
}


port = 23;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
   r = recv(socket:soc, length:8192);
   if ( "Password:" >!< r ) exit(0);
   s = string("1234\r\n");
   send(socket:soc, data:s);
   r = recv(socket:soc, length:8192);
   close(soc);
   if("ZyXEL" >< r || "ZyWALL" >< r )security_hole(port, extra: '\nAfter logging in using the password "1234", Nessus read this :\n\n  ' + r + '\n');
 }
}

#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description)
{
 script_id(10502);
 script_version ("$Revision: 1.16 $");
 script_xref(name:"OSVDB", value:"401");
 script_xref(name:"Secunia", value:"12353");

 script_cve_id("CVE-2001-1543");
 
 script_name(english:"Axis Camera Default Password");
 script_summary(english:"Checks for Axis Network Camera Default Password");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a default password set." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be an Axis Network Camera. It was possible to
log into the remote host with the default credentials 'root/pass'.

An attacker may use these credentials to trivially access the system." );
 script_set_attribute(attribute:"solution", value:
"Set a strong password for this account." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_require_ports(23);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('telnet_func.inc');
include('global_settings.inc');
if ( ! thorough_tests )exit(0);

port = 23;
if (get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
   banner = telnet_negotiate(socket:soc);
   req = string("root\r\n");
   send(socket:soc, data:req);
   recv(socket:soc, length:1000);
   req = string("pass\r\n");
   send(socket:soc, data:req);
   r = recv(socket:soc, length:1000);
   if("Root" >< r)security_hole(port);
   close(soc);
 }
}

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10045);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-1999-0889");
 script_xref(name:"OSVDB", value:"39");
 script_name(english:"Cisco 675 Router Default Unpassworded Account");
 script_summary(english:"Logs into the remote CISCO router");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router is not secured with a password."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote CISCO router is passwordless. A remote attacker could log\n",
     "in and take complete control of this device."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/bugtraq/1999-q3/0287.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/en/US/products/hw/modems/ps296/products_installation_guide_chapter09186a008007dd70.html"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Login to this router and set a strong password."
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
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
 if ( ! buf || "User Access Verification" >!< buf ) exit(0);
 soc = open_sock_tcp(port);
 if(soc)
 {
  buf = telnet_negotiate(socket:soc);
  if("User Access Verification" >< buf)
  {
   buf = recv(socket:soc, length:1024);
   data = string("\r\n");
   send(socket:soc, data:data);
   buf2 = recv(socket:soc, length:1024);
   if(">" >< buf2)security_hole(port);
  }
 close(soc);
 }
}

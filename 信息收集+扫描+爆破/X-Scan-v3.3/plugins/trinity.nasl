#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10501);
 script_version ("$Revision: 1.10 $");
 script_cve_id("CVE-2000-0138");
 script_xref(name:"OSVDB", value:"20");
 script_xref(name:"OSVDB", value:"295");
 
 script_name(english: "Trinity v3 Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has been compromised." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Trinity v3, a Trojan Horse that 
can be used to control your system or make it attack another network
(this is  actually called a Distributed Denial Of Service attack tool).

It is very likely that this host has been compromised" );
 script_set_attribute(attribute:"solution", value:
"Restore your system from backups, contact CERT and your local
authorities" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english: "Detects the presence of trinity v3");
 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2000-2009 Tenable Network Security, Inc.");
 script_family(english: "Backdoors");
 script_require_ports(33270);
 
 exit(0);
}

#
# The script code starts here
#

if(get_port_state(33270))
{
 soc = open_sock_tcp(33270);
 if(soc)
 {
  req = string("!@#\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  req = string("id\r\n");
  send(socket:soc, data:req);
  r = recv(socket:soc, length:16000);
  if("uid" >< r)security_hole(33270);
  close(soc);
 }
}

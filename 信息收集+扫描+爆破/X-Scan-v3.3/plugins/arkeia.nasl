#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{ 
 script_id(10018);
 script_bugtraq_id(661);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-1999-1534");
 script_xref(name:"OSVDB", value:"17");
 script_xref(name:"OSVDB", value:"11507");

 script_name(english:"Knox Arkeia Backup Service Buffer Overflow");
 script_summary(english:"Arkeia Buffer Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a backup service which is affected by a
local buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"It was possible to overflow a buffer in the Knox's 
Arkeia server.

This problem allows an attacker to perform a denial of service 
attack and to gain root using the remote service if the attacker is
local." );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 
 script_copyright(english:"This script is Copyright (C) 1999-2009 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("arkeia_default_account.nasl");
 script_require_ports(617);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) exit(0);

port = 617;
version = get_kb_item("arkeia-client/617");
if ( ! version ) exit(0);
if ( !ereg(pattern:"^[0-4]\.", string:version) )  exit(0);

if(safe_checks())
{
 security_hole(port);
 exit(0);
}


if(get_port_state(port))
{
 data = crap(10000);
 soc = open_sock_tcp(port);
 if(soc > 0)
 {
  send(socket:soc, data:data);
  close(soc);
  sleep(2);
  soc2 = open_sock_tcp(port);
  if(!soc2)security_hole(port);
  else close(soc2);
 }
}

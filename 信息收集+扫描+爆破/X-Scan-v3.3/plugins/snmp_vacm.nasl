#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10688);
 script_version ("$Revision: 1.20 $");

 script_cve_id("CVE-2004-1775");
 script_bugtraq_id(5030);
 script_xref(name:"OSVDB", value:"58150");

 script_name(english:"Cisco CatOS VACM read-write Community String Device Configuration Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The SNMP private community strings can be retrieved using SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the remote private community strings using
the View-Based Access Control MIB of the remote Cisco router. 

An attacker may use this flaw to gain read/write SNMP access on this
router." );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/warp/public/707/cisco-sa-20010228-ios-snmp-community.shtml" );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it, or
filter incoming UDP packets going to this port or install Cisco patch." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );
script_end_attributes();

 script_summary(english:"Enumerates communities via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl","snmp_sysDesc.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

#

include ("misc_func.inc");
include ("snmp_func.inc");

oid = get_kb_item("SNMP/OID");
if (!oid)
  exit (0);

# Only checks for cisco, else it could be FP
if (!is_valid_snmp_product(manufacturer:"1.3.6.1.4.1.9.1", oid:oid))
  exit (0);

community = get_kb_item("SNMP/community");
if(!community)exit(0);

port = get_kb_item("SNMP/port");
if(!port)port = 161;

soc = open_sock_udp(port);
if (!soc)
  exit (0);

comms = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.6.3.16.1.2.1.3");

if(strlen(comms))
{
 security_hole(port:port, extra: comms, protocol:"udp");
}

#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to Nicolas FISCHBACH (nico@securite.org) for his help
#


include("compat.inc");

if(description)
{
 script_id(11287);
 script_bugtraq_id(5613);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2002-1092","CVE-2002-1095");
 script_xref(name:"OSVDB", value:"8907");
 script_xref(name:"OSVDB", value:"8910");

 script_name(english:"Cisco VPN 3000 Concentrator Multiple Vulnerabilities (CSCdt56514, CSCdv66718)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote VPN concentrator is vulnerable to an internal PPTP / IPSEC
authentication login attack. 

This vulnerability is documented as Cisco bug ID CSCdt56514." );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003-2009 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 exit(0);
}


# The code starts here
ok=0;

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);




# Is this a VPN3k concentrator ?
if(!egrep(pattern:".*VPN 3000 Concentrator.*", string:os))exit(0);


# 3.6(Rel)
if(egrep(pattern:".*Version 3\.6\.Rel.*", string:os))ok = 1;

# 3.5(Rel)
if(egrep(pattern:".*Version 3\.5\.Rel.*", string:os))ok = 1;

# 3.5.x -> 3.5.4
if(egrep(pattern:".*Version 3\.5\.[0-4].*", string:os))ok = 1;

# 3.1.x -> 3.1.2
if(egrep(pattern:".*Version 3\.1\.Rel.*", string:os))ok = 1;
if(egrep(pattern:".*Version 3\.1\.[0-1][^0-9].*", string:os))ok = 1;

# < 3.0.3(B)
if(egrep(pattern:".*Version 3\.0\.[0-2].*", string:os))ok = 1;

# 2.x.x
if(egrep(pattern:".*Version 2\..*", string:os))ok = 1;



if(ok)security_hole(port:161, proto:"udp");

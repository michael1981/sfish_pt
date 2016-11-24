#
# (C) Tenable Network Security, Inc.
#
# Thanks to Nicolas FISCHBACH (nico@securite.org) for his help
#
# Ref:  http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml



include("compat.inc");

if(description)
{
 script_id(11297);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2002-1103");
 script_xref(name:"OSVDB", value:"8916");

 script_name(english:"Cisco VPN 3000 Concentrator Malformed ISAKMP Packet Remote DoS (CSCdy38035)");

 script_set_attribute(attribute:"synopsis", value:
"The remote VPN concentrator is affected by ISAKMP package processing
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote VPN concentrator is subject to an 
ISAKMP package processing vulnerability. Malformed or a very large 
number of ISAKMP packets might cause a reload of the concentrator. The 
vulnerability is aggravated if debug is turned on. This vulnerability 
is documented as Cisco bug ID CSCdy38035." );
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/warp/public/707/vpn3k-multiple-vuln-pub.shtml" );
 script_set_attribute(attribute:"solution", value:
"Apply vendor supplied patches." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );

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

# < 3.5.5
if(egrep(pattern:".*Version 3\.5\.Rel.*", string:os))ok = 1;
if(egrep(pattern:".*Version 3\.5\.[0-4][^0-9].*", string:os))ok = 1;

# 3.1.x
if(egrep(pattern:".*Version 3\.1\..*", string:os))ok = 1;

# 3.0.x
if(egrep(pattern:".*Version 3\.0\..*", string:os))ok = 1;

# 2.x.x
if(egrep(pattern:".*Version 2\..*", string:os))ok = 1;


if(ok)security_warning(port:161, proto:"udp");

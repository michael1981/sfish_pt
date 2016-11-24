#
# (C) Tenable Network Security
#


include("compat.inc");

if(description)
{
 script_id(15782);
 script_bugtraq_id(11649);
 script_cve_id("CVE-2004-1111");
  script_xref(name:"OSVDB", value:"11605");
 script_xref(name:"IAVA", value:"2004-b-0014");
 script_version("$Revision: 1.6 $");

 script_name(english:"Cisco IOS Malformed DHCP Packet DoS (CSCee50294)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote router contains a version of IOS which has flaw in the DHCP
service/relay service which may let an attacker to disable DHCP serving
and or relaying on the remote router.

CISCO identifies this vulnerability as bug id CSCee50294." );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/warp/public/707/cisco-sa-20041110-dhcp.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2004-2009 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl",
			 "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc",
			  "CISCO/model");
 exit(0);
}


# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.2EW
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)EW[0-9]*|12\.2\(18\)EW[0-1]),"))ok=1;

# 12.2EWA
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-9])\)|12\.2)EWA[0-9]*,"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-7])\)|12\.2)S[0-9]*|12\.2\(18\)S[0-5]),"))ok=1;

# 12.2SE
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-9])\)|12\.2)SE[0-9]*|12\.2\(20\)SE[0-2]),"))ok=1;

# 12.2SV
if(egrep(string:os, pattern:"(12\.2\(([0-9]|[1-1][0-9]|2[0-3])\)|12\.2)SV[0-9]*,"))ok=1;

# 12.2SW
if(egrep(string:os, pattern:"(12\.2\(([0-9]|[1-1][0-9]|2[0-4])\)|12\.2)SW[0-9]*,"))ok=1;

# 12.2SZ
if(egrep(string:os, pattern:"(12\.2\([0-9]*\)|12\.2)SZ[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");

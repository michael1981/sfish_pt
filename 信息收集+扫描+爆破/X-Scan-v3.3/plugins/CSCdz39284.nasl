#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#


include("compat.inc");

if(description)
{
 script_id(11380);
 script_version("$Revision: 1.9 $");
 script_cve_id("CVE-2003-1109");
 script_bugtraq_id(6904);
 script_xref(name:"OSVDB", value:"15412");

 script_name(english:"Cisco SIP Crafted INVITE Message Handling DoS (CSCdz39284, CSCdz41124)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote IOS crash when sending
it malformed SIP packets.

These vulnerabilities are documented as CISCO bug id CSCdz39284 and
CSCdz41124." );
 script_set_attribute(attribute:"solution", value:
"See http://www.cisco.com/warp/public/707/cisco-sa-20030221-protos.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003-2009 Tenable Network Security, Inc.");

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

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-2])\)|12\.2)T[0-9]*|12\.2\(13\)T[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");

#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Fixed broken link
#


include("compat.inc");

if(description)
{
 script_id(10973);
 script_bugtraq_id(315);
 script_cve_id("CVE-1999-0162");
 script_xref(name:"OSVDB", value:"796");
 script_version("$Revision: 1.10 $");

 script_name(english:"Cisco IOS established Keyword ACL Bypass (CSCdi34061)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"The remote seems to be vulnerable to a flaw in IOS when
the keyword 'established' is being used in the ACLs.

This bug can, under very specific circumstances and only with
certain IP host implementations, allow unauthorized packets to
circumvent a filtering router.

This vulnerability is documented as Cisco Bug ID CSCdi34061." );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/warp/public/707/2.html" );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2002-2009 Tenable Network Security, Inc.");

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
# 10.0
if(egrep(string:os, pattern:"(10\.0\([0-9]\)|10\.0),"))ok=1;

# 10.2
if(egrep(string:os, pattern:"(10\.2\([0-5]\)|10\.2),"))ok=1;

# 10.3
if(egrep(string:os, pattern:"(10\.3\([0-2]\)|10\.3),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");

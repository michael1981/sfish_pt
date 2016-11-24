#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#


include("compat.inc");

if(description)
{
 script_id(11056);
 script_xref(name:"IAVA", value:"2002-t-0014");
 script_bugtraq_id(5328);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2002-0813");
 script_xref(name:"OSVDB", value:"854");

 script_name(english:"Cisco TFTP Server Long Filename DoS (CSCdy03429)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"Trivial File Transfer Protocol (TFTP) is a protocol which allows for 
easy transfer of files between network connected devices. 

A vulnerability has been discovered in the processing of filenames within
a TFTP read request when Cisco IOS is configured to act as a TFTP server

This vulnerability is documented as Cisco Bug ID CSCdy03429" );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/warp/public/707/ios-tftp-long-filename-pub.shtml" );
 script_set_attribute(attribute:"risk_factor", value:"High" );
 script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2002-2009 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc");
 exit(0);
}


# The code starts here
ok=0;
os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);




# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);

# IOSes 11.1 to 11.3 are vulnerable
if(egrep(string:os, pattern:".* 11\.[1-3][^0-9].*"))
	security_hole(port:161, proto:"udp");


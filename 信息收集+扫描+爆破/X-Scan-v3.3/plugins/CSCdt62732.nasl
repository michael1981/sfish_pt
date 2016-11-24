#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CVE
#


include("compat.inc");

if(description)
{
 script_id(10980);
 script_bugtraq_id(2604);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2001-0429");
 script_xref(name:"OSVDB", value:"803");

 script_name(english:"Cisco Catalyst 5000 Series Frame STP Port Broadcast DoS (CSCdt62732)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"When an 802.1x (IEEE standard for port based network access control) 
frame is received by an affected Catalyst 5000 series switch on a STP 
(Spanning Tree Protocol) blocked port it is forwarded in that VLAN 
(Virtual Local Area Network) instead of being dropped. This causes a 
performance impacting 802.1x frames network storm in that part of the 
network, which is made up of the affected Catalyst 5000 series 
switches. This network storm only subsides when the source of the 
802.1x frames is removed or one of the workarounds in the workaround 
section is applied.


This vulnerability is documented as Cisco bug ID CSCdt62732." );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/warp/public/707/cat5k-8021x-vuln-pub.shtml" );
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




# Check for the required hardware...
#----------------------------------------------------------------
# catalyst5kRsfc
if(ereg(string:hardware, pattern:"^catalyst5kRsfc$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this CatOS ?
if(!egrep(pattern:".*Cisco Catalyst Operating System.*", string:os))exit(0);
# 4.5
if(egrep(string:os, pattern:"(4\.5\(([0-9]|1[0-1])\)|4\.5),"))ok=1;

# 5.5
if(egrep(string:os, pattern:"(5\.5\([0-6]\)|5\.5),"))ok=1;

# 6.3
if(egrep(string:os, pattern:"(6\.3\([0-2]\)|6\.3),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");

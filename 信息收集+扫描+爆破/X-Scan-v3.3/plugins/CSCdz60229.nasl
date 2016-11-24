#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#


include("compat.inc");

if(description)
{
 script_id(11383);
 script_cve_id("CVE-2002-1357", "CVE-2002-1358", "CVE-2002-1359", "CVE-2002-1360");
 script_bugtraq_id(6397, 6405, 6407, 6408, 6410);
 script_xref(name:"IAVA", value:"2003-t-0001");
 script_xref(name:"OSVDB", value:"8042");
 script_xref(name:"OSVDB", value:"8043");
 script_xref(name:"OSVDB", value:"8044");
 script_xref(name:"OSVDB", value:"8045");

 script_version("$Revision: 1.10 $");

 script_name(english:"Cisco SSH2 Server/Client Malformed Packet Remote DoS (CSCdz60229, CSCdy87221, CSCdu75477)");

 script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch" );
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote IOS crash when sending
it malformed SSH packets during the key exchange.

These flaws are documented as CISCO bug ID CSCdz60229, CSCdy87221 and 
CSCdu75477" );
 script_set_attribute(attribute:"solution", value:
"See 
http://www.cisco.com/warp/public/707/ssh-packet-suite-vuln.shtml" );
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
# 12.0S
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-2])\)|12\.0)S[0-9]*|12\.0\(23\)S[0-1]),"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"((12\.0\(([0-9]|[1-1][0-9]|2[0-0])\)|12\.0)ST[0-9]*|12\.0\(21\)ST[0-5]),"))ok=1;

# 12.1E
if(egrep(string:os, pattern:"((12\.1\(([0-9]|1[0-3])\)|12\.1)E[0-9]*|12\.1\(14\)E[0-0]),"))ok=1;

# 12.1EA
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)EA[0-9]*,"))ok=1;

# 12.1T
if(egrep(string:os, pattern:"(12\.1\([0-9]*\)|12\.1)T[0-9]*,"))ok=1;

# 12.2
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-2])\)|12\.2),"))ok=1;

# 12.2S
if(egrep(string:os, pattern:"(12\.2\(([0-9]|1[0-3])\)|12\.2)S[0-9]*,"))ok=1;

# 12.2T
if(egrep(string:os, pattern:"((12\.2\(([0-9]|1[0-2])\)|12\.2)T[0-9]*|12\.2\(13\)T[0-0]),"))ok=1;


#----------------------------------------------

if(ok)security_hole(port:161, proto:"udp");

#
# (C) Tenable Network Security, Inc.
#

# This vulnerability is tracked by three different bug IDs: CSCdr46528,
# CSCdt66560, and CSCds36541 


include("compat.inc");


if(description)
{
 script_id(10971);
 script_version("$Revision: 1.11 $");
 script_cve_id("CVE-2001-0861");
 script_bugtraq_id(3534);
 script_xref(name:"OSVDB", value:"794");

 script_name(english:"Cisco 12000 Series Router ICMP Unreachable DoS");
 script_summary(english:"Uses SNMP to determine if a flaw is present");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote router has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description", 
   value:string(
     "The remote device appears to be a Cisco 12000 Series router.\n",
     "According to its version number, it is vulnerable to a denial of\n",
     "service issue.  Forcing it to send a large number of ICMP unreachable\n",
     "packets can slow down throughput.  A remote attacker could use this to\n",
     "degrade the performance of the network."
   )
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://archives.neohapsis.com/archives/cisco/2001-q4/0005.html"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.cisco.com/warp/public/707/cisco-sa-20011114-gsr-unreachable.shtml"
 );
 script_set_attribute(
   attribute:"solution", 
   value:string(
     "Upgrade to the latest version of the software, or disable/rate\n",
     "limit the sending of ICMP unreachable packets."
   )
 );
 script_set_attribute(
   attribute:"cvss_vector", 
   value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P"
 );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is (C) 2002-2009 Tenable Network Security, Inc.");

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
# cisco12000
if(ereg(string:hardware, pattern:"^cisco12[0-9][0-9][0-9]$"))ok=1;

if(!ok)exit(0);
ok = 0;


# Check for the required operating system...
#----------------------------------------------------------------
# Is this IOS ?
if(!egrep(pattern:".*(Internetwork Operating|IOS).*", string:os))exit(0);
# 12.0S
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-6])\)|12\.0)S[0-9]*,"))ok=1;

# 12.0ST
if(egrep(string:os, pattern:"(12\.0\(([0-9]|1[0-5])\)|12\.0)ST[0-9]*,"))ok=1;


#----------------------------------------------

if(ok)security_warning(port:161, proto:"udp");

#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24740);
 script_version("$Revision: 1.7 $");
 script_cve_id("CVE-2007-0648");
 script_bugtraq_id(22330);
 script_xref(name:"OSVDB", value:"33051");

 script_name(english:"Cisco IOS SIP Packet Handling Remote DoS (CSCsh58082)");

 script_set_attribute(attribute:"synopsis", value:
"The remote CISCO device can be crashed remotely." );
 script_set_attribute(attribute:"description", value:
"The remote version of IOS contains a flaw which may cause the remote
router to crash when it receives a malicious SIP (Session Initiation
Protocol) packet. 

An attacker might use these flaws to disable this device remotely." );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/warp/public/707/cisco-sa-20070131-sip.shtml" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();


 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2007-2009 Tenable Network Security, Inc.");

 script_family(english:"CISCO");

 script_dependencie("snmp_sysDesc.nasl", "snmp_cisco_type.nasl");
 script_require_keys("SNMP/community", "SNMP/sysDesc", "CISCO/model");
 exit(0);
}


include('cisco_func.inc');

os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
version = extract_version(os);
if ( ! version ) exit(0);

if ( ! get_port_state(5060) ) exit(0);


#
# Is port 5060 open ? 
#
soc = open_sock_tcp(5060);
if ( ! soc ) exit(0);
else close(soc);



# 12.3 
if ( deprecated_version(version, "12.3T", "12.3XH", "12.3XQ", "12.3XR", "12.3XU", "12.3XW", "12.3XX", "12.3XY", "12.3YF", "12.3YG", "12.3YK", "12.3YM", "12.3YQ",  "12.3YT", "12.3YU", "12.3YX", "12.3YZ") ) vuln ++;

# 12.4
if ( deprecated_version(version, "12.4MR", "12.4SW", "12.4XA", "12.4XB", "12.4XC", "12.4XD", "12.4XE", "12.4XJ", "12.4XP", "12.4XT") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(4d)", "12.4(5b)", "12.4(7a)", "12.4(8)"),
		   newest:"12.4(8)") ) vuln ++;

if ( check_release(version:version,
		   patched:make_list("12.4(2)T5", "12.4(4)T3", "12.4(6)T1", "12.4(9)T"),
		   newest:"12.4(9)T") ) vuln ++;


if ( vuln == 1 ) security_hole(port:161, proto:"udp");
else if ( vuln > 1 ) display("Problem in script $Id: CSCsh58082.nasl,v 1.7 2009/10/26 20:57:20 mikhail Exp $\n");

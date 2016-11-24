#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(24019);
 script_version("$Revision: 1.8 $");
 script_cve_id("CVE-2007-0199");
 script_bugtraq_id(21990);
 script_xref(name:"OSVDB", value:"32683");

 script_name(english:"Cisco IOS Data-link Switching (DLSw) Capabilities Exchange Remote DoS (CSCsf28840)");

 script_set_attribute(attribute:"synopsis", value:
"The remote router can be crashed remotely." );
 script_set_attribute(attribute:"description", value:
"The remote host is a CISCO router containing a version of IOS that is
affected by a denial of service vulnerability. 

An attacker may exploit this flaw to crash the remote device." );
 script_set_attribute(attribute:"solution", value:
"http://www.cisco.com/en/US/products/products_security_advisory09186a00807bd128.shtml" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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
hardware = get_kb_item("CISCO/model"); if(!hardware)exit(0);
version = extract_version(os);
if ( ! version ) exit(0);


# 12.0
if ( deprecated_version(version, "12.0","12.0SZ", "12.0T", "12.0XA", "12.0XC", "12.0XD", "12.0XE", "12.0XG","12.0XH", "12.0XI", "12.0XK", "12.0XN", "12.0XQ", "12.0XR", "12.0XT" ) ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.0(18)S"),
		   newest:"12.0(18)S") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.0(5)WC17"),
		   newest:"12.0(5)WC17") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.0(4)XJ5"),
		   newest:"12.0(4)XJ5") ) vuln ++;


# 12.1

if ( deprecated_version(version, "12.1", "12.1AA", "12.1EC", "12.1EX", "12.1EZ", "12.1T", "12.1XA", "12.1XC", "12.1XD", "12.1XG", "12.1XH", "12.1XI", "12.1XJ", "12.1XM", "12.1XP", "12.1XQ", "12.1XS", "12.1XW", "12.1XX", "12.1XZ", "12.1YA", "12.1YB", "12.1YD", "12.1YI") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(26)E8", "12.1(27b)E2"),
		   newest:"12.1(27b)E2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(1)XE1"),
		   newest:"12.1(1)XE1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(3)XT2"),
		   newest:"12.1(3)XT2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.1(5)XV1"),
		   newest:"12.1(5)XV1") ) vuln ++;


# 12.2
if ( deprecated_version(version, "12.B", "12.2BW", "12.2BY", "12.2DD", "12.2DX", "12.2IXA", "12.2IXB", "12.2MC", "12.2SBC", "12.2SU", "12.2SX", "12.2SXA", "12.2SXB", "12.2SXD", "12.2SY", "12.2SZ", "12.2T", "12.2TPC", "12.2XA", "12.2XC", "12.2XD", "12.2XG", "12.2XH","12.2XJ", "12.2XK", "12.2XL", "12.2XM", "12.2XN", "12.2XQ", "12.2XT", "12.2XU", "12.2XW", "12.2YB", "12.2YC", "12.2YD", "12.2YE", "12.2YF", "12.2YH", "12.2YL", "12.2YM", "12.2YN", "12.2YT", "12.2YU", "12.2YW", "12.2YX", "12.2YY", "12.2YZ", "12.2ZA", "12.2ZB", "12.2ZD", "12.2ZE", "12.2ZF", "12.2ZL", "12.2ZN", "12.2ZU", "12.2ZW") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.2(43)"),
		   newest:"12.2(43)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(30)S"),
		   newest:"12.2(30)S") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(28)SB6", "12.2(31)SB2)"),
		   newest:"12.2(31)SB2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(33)SRA2"),
		   newest:"12.2(33)SRA2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(26)SV"),
		   newest:"12.2(26)SV") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(25)SW9"),
		   newest:"12.2(25)SW9") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXE6b"),
		   newest:"12.2(18)SXE6b") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(18)SXF8"),
		   newest:"12.2(18)SXF8") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(2)XB17"),
		   newest:"12.2(2)XB17") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(4)YA10"),
		   newest:"12.2(4)YA10") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(8)YJ1"),
		   newest:"12.2(8)YJ1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(11)YV1"),
		   newest:"12.2(11)YV1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(13)ZH6"),
		   newest:"12.2(13)ZH6") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.2(28a)ZV1"),
		   newest:"12.2(28a)ZV1") ) vuln ++;

#
# 12.3
#

if ( deprecated_version(version, "12.3B", "12.3BW", "12.3T", "12.3XB", "12.3XD", "12.3XF", "12.3XG", "12.3XH", "12.3XJ", "12.3XK", "12.3XQ", "12.3XR", "12.3XU", "12.3XW", "12.3YF", "12.3YH", "12.3YK", "12.3YM", "12.3YQ", "12.3YT", "12.3YU", "12.3YX", "12.3YZ") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(21)"),
		   newest:"12.3(21)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XA5"),
		   newest:"12.3(2)XA5") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XA5"),
		   newest:"12.3(2)XA5") ) vuln ++;


if ( check_release(version:version, 
		   patched:make_list("12.3(2)XC3"),
		   newest:"12.3(2)XC3") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(2)XE2"),
		   newest:"12.3(2)XE2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(7)XI8a"),
		   newest:"12.3(7)XI8a") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)XX2"),
		   newest:"12.3(8)XX2") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.3(8)YG5"),
		   newest:"12.3(8)YG5") ) vuln ++;


# 12.4
if ( deprecated_version(version, "12.4XA", "12.4XB", "12.4XE") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(7d)", "12.4(8c)", "12.4(10a)", "12.4(12)"),
		   newest:"12.4(12)") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(4)T4", "12.4(6)T6", "12.4(9)T3", "12.4(11)T1"),
		   newest:"12.4(11)T1") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(4)XC6"),
		   newest:"12.4(4)XC6") ) vuln ++;

if ( check_release(version:version, 
		   patched:make_list("12.4(4)XD5"),
		   newest:"12.4(4)XD5") ) vuln ++;


if ( vuln == 1 ) security_warning(port:161, proto:"udp");
else if ( vuln > 1 )  display("Problem in script $Id: CSCsf28840.nasl,v 1.8 2009/10/28 20:47:00 theall Exp $\n");



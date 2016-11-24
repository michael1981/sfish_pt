
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38924);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Wireshark 1.0.7 fixes various vulnerabilities (wireshark-6271)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wireshark-6271");
 script_set_attribute(attribute: "description", value: "Version upgrade to Wireshark 1.0.7 to fix various
vulnerabilities: CVE-2009-1269: crash while loading a
Tektronix .rf5 file CVE-2009-1268: crash in Check Point
High-Availability Protocol (CPHAP) dissector CVE-2009-1267:
LDAP dissector could crash on Windows CVE-2009-1210:
PROFINET format string bug CVE-2009-1266: additional
PROFINET  format string bugs, a crash in the PCNFSD
dissector
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch wireshark-6271");
script_end_attributes();

script_cve_id("CVE-2009-1269", "CVE-2009-1268", "CVE-2009-1267", "CVE-2009-1210", "CVE-2009-1266");
script_summary(english: "Check for the wireshark-6271 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wireshark-0.99.6-31.18", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"wireshark-devel-0.99.6-31.18", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

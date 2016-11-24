
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(34990);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  wireshark: fixed CVE-2008-3933, CVE-2008-4680-CVE-2008-4681 and CVE-2008-4683-CVE-2008-4685. (wireshark-5783)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch wireshark-5783");
 script_set_attribute(attribute: "description", value: "This update fixes problems that could crash wireshark when
processing compressed data (CVE-2008-3933) as well as
CVE-2008-4680 (USB dissector crash), CVE-2008-4681
(Bluetooth RFCOMM dissector crash), CVE-2008-4683
(Bluetooth ACL dissector crash), CVE-2008-4684 (PRP and
MATE dissector crash) and CVE-2008-4685 (Q.931 dissector
crash).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch wireshark-5783");
script_end_attributes();

script_cve_id("CVE-2008-3933", "CVE-2008-4680", "CVE-2008-4681", "CVE-2008-4683", "CVE-2008-4684", "CVE-2008-4685");
script_summary(english: "Check for the wireshark-5783 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"wireshark-0.99.5-5.15", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"wireshark-devel-0.99.5-5.15", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

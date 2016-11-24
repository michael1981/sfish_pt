
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42001);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  flash-player security update (flash-player-6387)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch flash-player-6387");
 script_set_attribute(attribute: "description", value: "Specially crafted Flash (SWF) files can cause a buffer
overflow in flash-player. Attackers could potentially
exploit that to execute arbitrary code (CVE-2009-1862,
CVE-2009-0901, CVE-2009-2395, CVE-2009-2493, CVE-2009-1863,
CVE-2009-1864, CVE-2009-1865, CVE-2009-1866, CVE-2009-1867,
CVE-2009-1868, CVE-2009-1869, CVE-2009-1870).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch flash-player-6387");
script_end_attributes();

script_cve_id("CVE-2009-1862", "CVE-2009-0901", "CVE-2009-2395", "CVE-2009-2493", "CVE-2009-1863", "CVE-2009-1864", "CVE-2009-1865", "CVE-2009-1866", "CVE-2009-1867", "CVE-2009-1868", "CVE-2009-1869", "CVE-2009-1870");
script_summary(english: "Check for the flash-player-6387 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"flash-player-9.0.246.0-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27336);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  libwmf: Security fix for heap overflow in WMF reader. (libwmf-1840)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libwmf-1840");
 script_set_attribute(attribute: "description", value: "A heap overflow could be triggered by specially crafted WMF
(Windows Meta Files) in the libwmf library. This problem
could be exploited to execute code, by a remote attacker
providing a file with embedded WMF data to an application
understanding this (like OpenOffice_org, abiword, gimp).

This issue is tracked by the Mitre CVE ID CVE-2006-3376.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch libwmf-1840");
script_end_attributes();

script_cve_id("CVE-2006-3376");
script_summary(english: "Check for the libwmf-1840 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libwmf-0.2.8.2-110.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libwmf-devel-0.2.8.2-110.5", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

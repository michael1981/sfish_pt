
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36004);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  ghostscript security update (ghostscript-devel-6065)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ghostscript-devel-6065");
 script_set_attribute(attribute: "description", value: "Integer overflows and missing upper bounds checks in
Ghostscript's ICC library potentially allowed attackers to
crash Ghostscript or even cause execution of arbitrary code
via specially crafted PS or PDF files (CVE-2009-0583,
CVE-2009-0584).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch ghostscript-devel-6065");
script_end_attributes();

script_cve_id("CVE-2009-0583", "CVE-2009-0584");
script_summary(english: "Check for the ghostscript-devel-6065 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ghostscript-fonts-other-8.15.4-3.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-rus-8.15.4-3.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-std-8.15.4-3.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-ijs-devel-8.15.4-3.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-library-8.15.4-3.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-omni-8.15.4-3.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-x11-8.15.4-3.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libgimpprint-4.2.7-178.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libgimpprint-devel-4.2.7-178.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

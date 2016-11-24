
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(36007);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  lcms security update (liblcms-6049)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch liblcms-6049");
 script_set_attribute(attribute: "description", value: "Specially crafted image files could cause an integer
overflow in lcms. Attackers could potentially exploit that
to crash applications using lcms or even execute arbitrary
code (CVE-2009-0723, CVE-2009-0581, CVE-2009-0733).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch liblcms-6049");
script_end_attributes();

script_cve_id("CVE-2009-0723", "CVE-2009-0581", "CVE-2009-0733");
script_summary(english: "Check for the liblcms-6049 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"liblcms-1.16-39.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"liblcms-32bit-1.16-39.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"liblcms-64bit-1.16-39.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"liblcms-devel-1.16-39.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"liblcms-devel-32bit-1.16-39.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"liblcms-devel-64bit-1.16-39.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

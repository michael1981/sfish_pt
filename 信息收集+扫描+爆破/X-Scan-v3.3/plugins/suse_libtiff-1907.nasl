
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27334);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  libtiff: Various remotely exploitable bugs fixed (libtiff-1907)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libtiff-1907");
 script_set_attribute(attribute: "description", value: "This update of libtiff is the result of a source-code audit
done by Tavis Ormandy. It fixes various bugs that can lead
to denial-of-service conditions as well as to remote code
execution while parsing a tiff image. (CVE-2006-3459,
CVE-2006-3460, CVE-2006-3461, CVE-2006-3462, CVE-2006-3463,
CVE-2006-3464, CVE-2006-3465)

Please restart your applications.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch libtiff-1907");
script_end_attributes();

script_cve_id("CVE-2006-3459", "CVE-2006-3460", "CVE-2006-3461", "CVE-2006-3462", "CVE-2006-3463", "CVE-2006-3464", "CVE-2006-3465");
script_summary(english: "Check for the libtiff-1907 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libtiff-3.8.2-5.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff-32bit-3.8.2-5.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff-64bit-3.8.2-5.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff-devel-3.8.2-5.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff-devel-32bit-3.8.2-5.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff-devel-64bit-3.8.2-5.9", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

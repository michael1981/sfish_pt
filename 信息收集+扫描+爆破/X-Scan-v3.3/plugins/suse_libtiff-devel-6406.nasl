
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42018);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  tiff tools integer overflows (libtiff-devel-6406)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libtiff-devel-6406");
 script_set_attribute(attribute: "description", value: "This update of the tiff package fixes various integer
overflows in the tools. (CVE-2009-2347)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch libtiff-devel-6406");
script_end_attributes();

script_cve_id("CVE-2009-2347");
script_summary(english: "Check for the libtiff-devel-6406 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libtiff-devel-3.8.2-68.7", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff-devel-32bit-3.8.2-68.7", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff-devel-64bit-3.8.2-68.7", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff3-3.8.2-68.7", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff3-32bit-3.8.2-68.7", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libtiff3-64bit-3.8.2-68.7", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tiff-3.8.2-68.7", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38807);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  ghostscript security update (ghostscript-devel-6246)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ghostscript-devel-6246");
 script_set_attribute(attribute: "description", value: "Specially crafted file could cause a heap-overflow in JBIG2
decoder (CVE-2009-0196), an integer overflow in ICC library
(CVE-2009-0792), a buffer overflow in BaseFont writer
module (CVE-2008-6679) or crash the CCITTFax decoder
(CVE-2007-6725).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch ghostscript-devel-6246");
script_end_attributes();

script_cve_id("CVE-2009-0196", "CVE-2009-0792", "CVE-2008-6679", "CVE-2007-6725");
script_summary(english: "Check for the ghostscript-devel-6246 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ghostscript-fonts-other-8.15.4-3.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-rus-8.15.4-3.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-fonts-std-8.15.4-3.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-ijs-devel-8.15.4-3.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-library-8.15.4-3.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-omni-8.15.4-3.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ghostscript-x11-8.15.4-3.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libgimpprint-4.2.7-178.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libgimpprint-devel-4.2.7-178.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

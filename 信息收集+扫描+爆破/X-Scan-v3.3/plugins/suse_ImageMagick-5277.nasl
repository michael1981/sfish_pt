
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33379);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  ImageMagick: Fix security problems in XCF and PCX decoders (ImageMagick-5277)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ImageMagick-5277");
 script_set_attribute(attribute: "description", value: "ImageMagick is affected by two security problems:

CVE-2008-1096: Buffer overflow in the handling of XCF files
CVE-2008-1097: Heap buffer overflow in the handling of PCX
files
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ImageMagick-5277");
script_end_attributes();

script_cve_id("CVE-2008-1096", "CVE-2008-1097");
script_summary(english: "Check for the ImageMagick-5277 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ImageMagick-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-extra-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libMagick++-devel-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libMagick++10-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libMagick10-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libWand10-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.3.5.10-2.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

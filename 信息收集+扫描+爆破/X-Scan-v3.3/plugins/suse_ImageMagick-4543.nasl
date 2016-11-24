
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27604);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  ImageMagick: Fix for several security bugs (ImageMagick-4543)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ImageMagick-4543");
 script_set_attribute(attribute: "description", value: "This update of ImageMagick fixes several vulnerabilities.
- CVE-2007-4985: infinite loop while parsing images
- CVE-2007-4986: integer overflows that can lead to code
  execution
- CVE-2007-4987: one-byte buffer overflow that can lead to
  code execution (SLES8- and SLES9-based products are not
  affected)
- CVE-2007-4988: integer overflows that can lead to code
  execution
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch ImageMagick-4543");
script_end_attributes();

script_cve_id("CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988");
script_summary(english: "Check for the ImageMagick-4543 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ImageMagick-6.3.0.0-27.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-6.3.0.0-27.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-Magick++-devel-6.3.0.0-27.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ImageMagick-devel-6.3.0.0-27.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-PerlMagick-6.3.0.0-27.8", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

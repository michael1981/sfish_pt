
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27603);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  GraphicsMagick: Fix for several security bugs (GraphicsMagick-4539)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch GraphicsMagick-4539");
 script_set_attribute(attribute: "description", value: "This update of GraphicsMagick fixes several vulnerabilities.
- CVE-2007-4985: infinite loop while parsing images
- CVE-2007-4986: integer overflows that can lead to code
  execution
- CVE-2007-4987: one-byte buffer overflow that can lead to
  code execution
- CVE-2007-4988: integer overflows that can lead to code
  execution
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch GraphicsMagick-4539");
script_end_attributes();

script_cve_id("CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4987", "CVE-2007-4988");
script_summary(english: "Check for the GraphicsMagick-4539 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"GraphicsMagick-1.1.8-20.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"GraphicsMagick-devel-1.1.8-20.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagick++-devel-1.1.8-20.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagick++1-1.1.8-20.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagick1-1.1.8-20.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagickWand0-1.1.8-20.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-GraphicsMagick-1.1.8-20.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

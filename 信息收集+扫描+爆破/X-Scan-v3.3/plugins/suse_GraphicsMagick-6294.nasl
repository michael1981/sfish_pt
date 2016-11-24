
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39497);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  GraphicsMagick: Integer overflow in XMakeImage() (GraphicsMagick-6294)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch GraphicsMagick-6294");
 script_set_attribute(attribute: "description", value: "This update of GraphicsMagick fixes an integer overflow in
the XMakeImage() function that allowed remote attackers to
cause a denial-of-service and possibly the execution of
arbitrary code via a crafted TIFF file. (CVE-2009-1882)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch GraphicsMagick-6294");
script_end_attributes();

script_cve_id("CVE-2009-1882");
script_summary(english: "Check for the GraphicsMagick-6294 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"GraphicsMagick-1.1.8-20.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"GraphicsMagick-devel-1.1.8-20.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagick++-devel-1.1.8-20.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagick++1-1.1.8-20.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagick1-1.1.8-20.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libGraphicsMagickWand0-1.1.8-20.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-GraphicsMagick-1.1.8-20.8", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

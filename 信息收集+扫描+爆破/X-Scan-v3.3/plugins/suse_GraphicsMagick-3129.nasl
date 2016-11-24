
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27103);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  GraphicsMagick: This update fixes three integer overflows (GraphicsMagick-3129)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch GraphicsMagick-3129");
 script_set_attribute(attribute: "description", value: "This update of GraphicsMagick fixes three integer overflow
in DCM and XWD code. These bugs can be exploited remotely
via other application. (CVE-2007-1667,CVE-2007-1797)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch GraphicsMagick-3129");
script_end_attributes();

script_cve_id("CVE-2007-1667", "CVE-2007-1797");
script_summary(english: "Check for the GraphicsMagick-3129 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"GraphicsMagick-1.1.7-35.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"GraphicsMagick-c++-1.1.7-35.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"GraphicsMagick-c++-devel-1.1.7-35.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"GraphicsMagick-devel-1.1.7-35.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"perl-GraphicsMagick-1.1.7-35.3", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

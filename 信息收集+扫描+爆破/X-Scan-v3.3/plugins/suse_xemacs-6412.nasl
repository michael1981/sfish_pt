
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42040);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  xemacs: security update for integer overflows and improved font handling (xemacs-6412)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xemacs-6412");
 script_set_attribute(attribute: "description", value: "Specially crafted tiff, png and jpeg images could cause
integer overflows in xemacs and possible system compromise.
(CVE-2009-2688) Additionally two non-security bugs were
fixed that enable xemacs to use the configured fonts.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch xemacs-6412");
script_end_attributes();

script_cve_id("CVE-2009-2688");
script_summary(english: "Check for the xemacs-6412 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xemacs-21.5.28.20070807-24.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xemacs-el-21.5.28.20070807-24.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xemacs-info-21.5.28.20070807-24.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(38846);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  xine-lib: QuickTime movie integer overflow (xine-devel-6230)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xine-devel-6230");
 script_set_attribute(attribute: "description", value: "This update of xine-lib fixes an integer overflow in the
qt_error parse_trak_atom() function in that leads to a
heap-based overflow and  allows remote attackers to execute
arbitrary code via a malformed Quicktime movie file.
(CVE-2009-1274)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch xine-devel-6230");
script_end_attributes();

script_cve_id("CVE-2009-1274");
script_summary(english: "Check for the xine-devel-6230 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xine-devel-1.1.8-14.16", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-extra-1.1.8-14.16", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-lib-1.1.8-14.16", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-lib-32bit-1.1.8-14.16", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-lib-64bit-1.1.8-14.16", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

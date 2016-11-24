
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31781);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  xine-lib security update (xine-devel-5137)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xine-devel-5137");
 script_set_attribute(attribute: "description", value: "Specially crafted files could cause integer overflows in
the xine library. Attackers could potentially exploit that
to execute arbitrary code with the privileges of the user
who opened such a file (CVE-2008-1482).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch xine-devel-5137");
script_end_attributes();

script_cve_id("CVE-2008-1482");
script_summary(english: "Check for the xine-devel-5137 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xine-devel-1.1.8-14.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-extra-1.1.8-14.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-lib-1.1.8-14.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-lib-32bit-1.1.8-14.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-lib-64bit-1.1.8-14.6", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xine-ui-0.99.5-62.2", release:"SUSE10.3") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");


#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42036);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  subversion: fix for buffer overflows in client and server. (subversion-6418)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch subversion-6418");
 script_set_attribute(attribute: "description", value: "This update of subversion some buffer overflows in the
client and server code that can occur while parsing binary
diffs. (CVE-2009-2411)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch subversion-6418");
script_end_attributes();

script_cve_id("CVE-2009-2411");
script_summary(english: "Check for the subversion-6418 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"subversion-1.4.4-30.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subversion-devel-1.4.4-30.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subversion-perl-1.4.4-30.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subversion-python-1.4.4-30.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subversion-server-1.4.4-30.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"subversion-tools-1.4.4-30.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

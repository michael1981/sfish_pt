
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33924);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  python: multiple security vulnerabilities got fixed (python-5491)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch python-5491");
 script_set_attribute(attribute: "description", value: "This update of python fixes several security
vulnerabilities. (CVE-2008-1679,CVE-2008-1887,
CVE-2008-3143, CVE-2008-3142, CVE-2008-3144, CVE-2008-2315,
CVE-2008-2316)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch python-5491");
script_end_attributes();

script_cve_id("CVE-2008-1679", "CVE-2008-1887", "CVE-2008-3143", "CVE-2008-3142", "CVE-2008-3144", "CVE-2008-2315", "CVE-2008-2316");
script_summary(english: "Check for the python-5491 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"python-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-32bit-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-64bit-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-curses-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-demo-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-devel-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-gdbm-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-idle-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-tk-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"python-xml-2.5.1-39.6", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

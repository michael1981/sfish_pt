
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(34028);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  ruby: fix for several security vulnerabilities (ruby-5483)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ruby-5483");
 script_set_attribute(attribute: "description", value: "This update of ruby fixes: 
- a possible information leakage (CVE-2008-1145) 
- a directory traversal bug (CVE-2008-1891) in WEBrick 
- various memory corruptions and integer overflows in array
  and string handling (CVE-2008-2662, CVE-2008-2663,
  CVE-2008-2664, CVE-2008-2725, CVE-2008-2726,
  CVE-2008-2727, CVE-2008-2728)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch ruby-5483");
script_end_attributes();

 script_cve_id("CVE-2008-1145", "CVE-2008-1891", "CVE-2008-2662", "CVE-2008-2664", "CVE-2008-2725");
script_summary(english: "Check for the ruby-5483 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ruby-1.8.6.p36-20.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.6.p36-20.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ruby-doc-html-1.8.6.p36-20.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ruby-doc-ri-1.8.6.p36-20.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ruby-examples-1.8.6.p36-20.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ruby-test-suite-1.8.6.p36-20.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.6.p36-20.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

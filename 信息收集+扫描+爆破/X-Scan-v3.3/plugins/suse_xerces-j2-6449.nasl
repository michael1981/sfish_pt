
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41599);
 script_version ("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  Security update for Xerces-j2 (xerces-j2-6449)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch xerces-j2-6449");
 script_set_attribute(attribute: "description", value: "The xerces-j2 package was vulnerable to various bugs while
parsing XML.CVE-2009-2625 has been assigned to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch xerces-j2-6449");
script_end_attributes();

script_cve_id("CVE-2009-2625");
script_summary(english: "Check for the xerces-j2-6449 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"xerces-j2-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-demo-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-javadoc-apis-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-javadoc-dom3-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-javadoc-impl-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-javadoc-other-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-javadoc-xni-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-scripts-2.7.1-16.7", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

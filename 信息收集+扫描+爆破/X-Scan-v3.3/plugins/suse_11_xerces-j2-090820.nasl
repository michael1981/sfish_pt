
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41462);
 script_version("$Revision: 1.1 $");
 script_name(english: "SuSE Security Update:  xerces-j2 (2009-08-20)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for xerces-j2");
 script_set_attribute(attribute: "description", value: "The xerces-j2 package was vulnerable to various bugs while
parsing XML.CVE-2009-2625 has been assigned to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for xerces-j2");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=530717");
script_end_attributes();

 script_cve_id("CVE-2009-2625");
script_summary(english: "Check for the xerces-j2 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"xerces-j2-2.8.1-238.27.1", release:"SLES11", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-xml-apis-2.8.1-238.27.1", release:"SLES11", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-xml-resolver-2.8.1-238.27.1", release:"SLES11", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"xerces-j2-2.8.1-238.27.1", release:"SLED11", cpu:"noarch") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");

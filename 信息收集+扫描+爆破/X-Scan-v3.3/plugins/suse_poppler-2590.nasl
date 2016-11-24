
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(27398);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  poppler: Securityupdate to fix a vulnerability which occurs while processing a special PDF file. (poppler-2590)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch poppler-2590");
 script_set_attribute(attribute: "description", value: "This update fixes a vulnerability which occurs while
processing a special PDF file. This bug can lead to a
denial-of-service condition, or a memory corruption, or to
arbitrary code execution. (CVE-2007-0104)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch poppler-2590");
script_end_attributes();

script_cve_id("CVE-2007-0104");
script_summary(english: "Check for the poppler-2590 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"poppler-0.5.4-33.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"poppler-devel-0.5.4-33.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");

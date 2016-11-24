
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38137);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:033: sudo");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:033 (sudo).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been identified in sudo which allowed - depending
on the sudoers rules - a sudo-user to execute arbitrary shell commands
as root (CVE-2009-0034).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:033");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-0034");
script_summary(english: "Check for the version of the sudo package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sudo-1.6.9p5-1.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.9p13-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sudo-1.6.9p17-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sudo-", release:"MDK2008.0")
 || rpm_exists(rpm:"sudo-", release:"MDK2008.1")
 || rpm_exists(rpm:"sudo-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-0034", value:TRUE);
}
exit(0, "Host is not affected");

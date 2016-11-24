
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(25428);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:110: php-pear");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:110 (php-pear).");
 script_set_attribute(attribute: "description", value: "A security hole was discovered in all versions of the PEAR Installer
(http://pear.php.net/PEAR). The security hole is the most serious
hole found to date in the PEAR Installer, and would allow a malicious
package to install files anywhere in the filesystem.
The vulnerability only affects users who are installing an
intentionally created package with a malicious intent. Because the
package is easily traced to its source, this is most likely to happen
if a hacker were to compromise a PEAR channel server and alter a
package to install a backdoor. In other words, it must be combined
with other exploits to be a problem.
Updated packages have been patched to prevent this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:110");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-2519");
script_summary(english: "Check for the version of the php-pear package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"php-pear-5.1.6-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pear-5.1.6-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pear-5.2.1-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-pear-5.2.1-2.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"php-pear-", release:"MDK2007.0")
 || rpm_exists(rpm:"php-pear-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-2519", value:TRUE);
}
exit(0, "Host is not affected");

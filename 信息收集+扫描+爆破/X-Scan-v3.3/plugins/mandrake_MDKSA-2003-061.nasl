
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14044);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:061: gnupg");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:061 (gnupg).");
 script_set_attribute(attribute: "description", value: "A bug was discovered in GnuPG versions 1.2.1 and earlier. When gpg
evaluates trust values for different UIDs assigned to a key, it would
incorrectly associate the trust value of the UID with the highest
trust value with every other UID assigned to that key. This prevents
a warning message from being given when attempting to encrypt to an
invalid UID, but due to the bug, is accepted as valid.
Patches have been applied for version 1.0.7 and all users are
encouraged to upgrade.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:061");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0255");
script_summary(english: "Check for the version of the gnupg package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnupg-1.0.7-3.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.0.7-3.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnupg-1.2.2-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gnupg-", release:"MDK8.2")
 || rpm_exists(rpm:"gnupg-", release:"MDK9.0")
 || rpm_exists(rpm:"gnupg-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0255", value:TRUE);
}
exit(0, "Host is not affected");

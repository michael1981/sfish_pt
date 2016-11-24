
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14038);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:054: man");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:054 (man).");
 script_set_attribute(attribute: "description", value: "A difficult to exploit vulnerability was discovered in versions of man
prior to 1.5l. A bug exists in man that could cause a program named
'unsafe' to be executed due to a malformed man file. In order to
exploit this bug, a local attacker would have to be able to get another
user to read the malformed man file, and the attacker would also have
to create a file called 'unsafe' that would be located somewhere in the
victim's path.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:054");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0124");
script_summary(english: "Check for the version of the man package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"man-1.5j-4.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"man-1.5k-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"man-1.5k-8.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"man-", release:"MDK8.2")
 || rpm_exists(rpm:"man-", release:"MDK9.0")
 || rpm_exists(rpm:"man-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0124", value:TRUE);
}
exit(0, "Host is not affected");

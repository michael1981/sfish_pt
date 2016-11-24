
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14010);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:026: shadow-utils");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:026 (shadow-utils).");
 script_set_attribute(attribute: "description", value: "The shadow-utils package contains the tool useradd, which is used to
create or update new user information. When useradd creates an
account, it would create it with improper permissions; instead of
having it owned by the group mail, it would be owned by the user's
primary group. If this is a shared group (ie. 'users'), then all
members of the shared group would be able to obtain access to the
mail spools of other members of the same group. A patch to useradd
has been applied to correct this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:026");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-1509");
script_summary(english: "Check for the version of the shadow-utils package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"shadow-utils-20000902-2.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-20000902-5.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"shadow-utils-20000902-8.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"shadow-utils-", release:"MDK8.1")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK8.2")
 || rpm_exists(rpm:"shadow-utils-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-1509", value:TRUE);
}
exit(0, "Host is not affected");

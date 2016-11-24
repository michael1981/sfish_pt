
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14070);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:088: pam_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:088 (pam_ldap).");
 script_set_attribute(attribute: "description", value: "A bug was fixed in pam_ldap 162 with the pam_filter mechanism which is
commonly used for host-based access restriction in environments using
LDAP for authentication. Mandrake Linux 9.1 provided pam_ldap 161
which had this problem and as a result, systems relying on pam_filter
for host-based access restriction would allow any user, regardless of
the host attribute associated with their account, to log into the
system. All users who use LDAP-based authentication are encouraged to
upgrade immediately.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:088");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0734");
script_summary(english: "Check for the version of the pam_ldap package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nss_ldap-207-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-164-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pam_ldap-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0734", value:TRUE);
}
exit(0, "Host is not affected");

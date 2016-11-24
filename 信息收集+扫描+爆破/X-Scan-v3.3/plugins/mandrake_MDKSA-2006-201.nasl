
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24586);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:201: pam_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:201 (pam_ldap).");
 script_set_attribute(attribute: "description", value: "Pam_ldap does not return an error condition when an LDAP directory
server responds with a PasswordPolicyResponse control response, which
causes the pam_authenticate function to return a success code even if
authentication has failed, as originally reported for xscreensaver.
This might lead to an attacker being able to login into a suspended
system account.
Updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:201");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-5170");
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

if ( rpm_check( reference:"pam_ldap-180-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-180-4.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"pam_ldap-", release:"MDK2006.0")
 || rpm_exists(rpm:"pam_ldap-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-5170", value:TRUE);
}
exit(0, "Host is not affected");

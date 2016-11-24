
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37403);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:049: nss_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:049 (nss_ldap).");
 script_set_attribute(attribute: "description", value: "A race condition in nss_ldap, when used in applications that use
pthread and fork after a call to nss_ldap, does not properly handle the
LDAP connection, which might cause nss_ldap to return the wrong user
data to the wrong process, giving one user access to data belonging
to another user, in some cases.
The updated package hais been patched to prevent this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:049");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-5794");
script_summary(english: "Check for the version of the nss_ldap package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nss_ldap-250-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"nss_ldap-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2007-5794", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13974);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2002:075: nss_ldap");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2002:075 (nss_ldap).");
 script_set_attribute(attribute: "description", value: "A buffer overflow vulnerability exists in nss_ldap versions prior to
198. When nss_ldap is configured without a value for the 'host'
keyword, it attempts to configure itself using SRV records stored in
DNS. nss_ldap does not check that the data returned by the DNS query
will fit into an internal buffer, thus exposing it to an overflow.
A similar issue exists in versions of nss_ldap prior to 199 where
nss_ldap does not check that the data returned by the DNS query has not
been truncated by the resolver libraries to avoid a buffer overflow.
This can make nss_ldap attempt to parse more data than what is actually
available, making it vulnerable to a read buffer overflow.
Finally, a format string bug in the logging function of pam_ldap prior
to version 144 exist.
All users are recommended to upgrade to these updated packages. Note
that the nss_ldap packages for 7.2, 8.0, and Single Network Firewall
7.2 contain the pam_ldap modules.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:075");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2002-0374", "CVE-2002-0825");
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

if ( rpm_check( reference:"nss_ldap-202-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-156-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-156-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"nss_ldap-202-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam_ldap-156-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"nss_ldap-", release:"MDK7.2")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK8.0")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK8.1")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK8.2")
 || rpm_exists(rpm:"nss_ldap-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2002-0374", value:TRUE);
 set_kb_item(name:"CVE-2002-0825", value:TRUE);
}
exit(0, "Host is not affected");

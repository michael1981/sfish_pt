
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14122);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:023: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:023 (openssl).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered by the OpenSSL group using the
Codenomicon TLS Test Tool. The test uncovered a null-pointer
assignment in the do_change_cipher_spec() function whih could be
abused by a remote attacker crafting a special SSL/TLS handshake
against a server that used the OpenSSL library in such a way as to
cause OpenSSL to crash. Depending on the application in question,
this could lead to a Denial of Service (DoS). This vulnerability
affects both OpenSSL 0.9.6 (0.9.6c-0.9.6k) and 0.9.7 (0.9.7a-0.9.7c).
CVE has assigned CVE-2004-0079 to this issue.
Another vulnerability was discovered by Stephen Henson in OpenSSL
versions 0.9.7a-0.9.7c; there is a flaw in the SSL/TLS handshaking
code when using Kerberos ciphersuites. A remote attacker could
perform a carefully crafted SSL/TLS handshake against a server
configured to use Kerberos ciphersuites in such a way as to cause
OpenSSL to crash. CVE has assigned CVE-2004-0112 to this issue.
Mandrakesoft urges users to upgrade to the packages provided that have
been patched to protect against these problems. We would also like to
thank NISCC for their assistance in coordinating the disclosure of
these problems.
Please note that you will need to restart any SSL-enabled services for
the patch to be effective, including (but not limited to) Apache,
OpenLDAP, etc.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:023");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0079", "CVE-2004-0112");
script_summary(english: "Check for the version of the openssl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libopenssl0-0.9.6i-1.7.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.7.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-static-devel-0.9.6i-1.7.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.7.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7a-1.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7a-1.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7a-1.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-1.3.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7b-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7b-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7b-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7b-4.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK9.0")
 || rpm_exists(rpm:"openssl-", release:"MDK9.1")
 || rpm_exists(rpm:"openssl-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0079", value:TRUE);
 set_kb_item(name:"CVE-2004-0112", value:TRUE);
}
exit(0, "Host is not affected");

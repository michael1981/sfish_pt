
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(23905);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:161: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:161 (openssl).");
 script_set_attribute(attribute: "description", value: "Daniel Bleichenbacher recently described an attack on PKCS #1 v1.5
signatures where an RSA key with a small exponent used could be
vulnerable to forgery of a PKCS #1 v1.5 signature signed by that
key.
Any software using OpenSSL to verify X.509 certificates is potentially
vulnerable to this issue, as well as any other use of PKCS #1 v1.5,
including software uses OpenSSL for SSL or TLS.
Updated packages are patched to address this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:161");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-4339");
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

if ( rpm_check( reference:"libopenssl0.9.7-0.9.7g-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7g-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7g-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7g-2.3.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-4339", value:TRUE);
}
exit(0, "Host is not affected");

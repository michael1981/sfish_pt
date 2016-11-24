
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(26950);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:193: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:193 (openssl).");
 script_set_attribute(attribute: "description", value: "A flaw in how OpenSSL performed Montgomery multiplications was
discovered %that could allow a local attacker to reconstruct
RSA private keys by examining another user's OpenSSL processes
(CVE-2007-3108).
Moritz Jodeit found that OpenSSL's SSL_get_shared_ciphers() function
did not correctly check the size of the buffer it was writing to.
As a result, a remote attacker could exploit this to write one NULL
byte past the end of the applications's cipher list buffer, which could
possibly lead to a denial of service or the execution of arbitrary code
(CVE-2007-5135).
Updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:193");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-3108", "CVE-2007-5135");
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

if ( rpm_check( reference:"libopenssl0.9.8-0.9.8b-2.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8b-2.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8b-2.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8b-2.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-0.9.8e-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8e-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8e-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8e-2.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK2007.0")
 || rpm_exists(rpm:"openssl-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-3108", value:TRUE);
 set_kb_item(name:"CVE-2007-5135", value:TRUE);
}
exit(0, "Host is not affected");

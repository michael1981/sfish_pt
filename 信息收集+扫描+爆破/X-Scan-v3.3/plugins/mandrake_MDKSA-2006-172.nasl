
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24558);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:172-1: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:172-1 (openssl).");
 script_set_attribute(attribute: "description", value: "Dr S N Henson of the OpenSSL core team and Open Network Security
recently developed an ASN1 test suite for NISCC (www.niscc.gov.uk).
When the test suite was run against OpenSSL two denial of service
vulnerabilities were discovered.
During the parsing of certain invalid ASN1 structures an error
condition is mishandled. This can result in an infinite loop which
consumes system memory. (CVE-2006-2937)
Certain types of public key can take disproportionate amounts of time
to process. This could be used by an attacker in a denial of service
attack. (CVE-2006-2940)
Tavis Ormandy and Will Drewry of the Google Security Team discovered a
buffer overflow in the SSL_get_shared_ciphers utility function, used by
some applications such as exim and mysql. An attacker could send a
list of ciphers that would overrun a buffer. (CVE-2006-3738)
Tavis Ormandy and Will Drewry of the Google Security Team discovered a
possible DoS in the sslv2 client code. Where a client application uses
OpenSSL to make a SSLv2 connection to a malicious server that server
could cause the client to crash. (CVE-2006-4343)
Updated packages are patched to address these issues.
Update:
There was an error in the original published patches for CVE-2006-2940.
New packages have corrected this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:172-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-2937", "CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
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

if ( rpm_check( reference:"libopenssl0.9.7-0.9.7g-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7g-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7g-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7g-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7g-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7g-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7g-2.5.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-0.9.8b-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8b-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8b-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8b-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-0.9.8b-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8b-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8b-2.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK2006.0")
 || rpm_exists(rpm:"openssl-", release:"MDK2007.0") )
{
 set_kb_item(name:"CVE-2006-2937", value:TRUE);
 set_kb_item(name:"CVE-2006-2940", value:TRUE);
 set_kb_item(name:"CVE-2006-3738", value:TRUE);
 set_kb_item(name:"CVE-2006-4343", value:TRUE);
}
exit(0, "Host is not affected");

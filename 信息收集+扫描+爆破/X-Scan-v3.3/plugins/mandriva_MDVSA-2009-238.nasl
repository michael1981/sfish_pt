
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(41030);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:238: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:238 (openssl).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities was discovered and corrected in openssl:
Use-after-free vulnerability in the dtls1_retrieve_buffered_fragment
function in ssl/d1_both.c in OpenSSL 1.0.0 Beta 2 allows remote
attackers to cause a denial of service (openssl s_client crash)
and possibly have unspecified other impact via a DTLS packet, as
demonstrated by a packet from a server that uses a crafted server
certificate (CVE-2009-1379).
ssl/s3_pkt.c in OpenSSL before 0.9.8i allows remote attackers to
cause a denial of service (NULL pointer dereference and daemon crash)
via a DTLS ChangeCipherSpec packet that occurs before ClientHello
(CVE-2009-1386).
The dtls1_retrieve_buffered_fragment function in ssl/d1_both.c
in OpenSSL before 1.0.0 Beta 2 allows remote attackers to cause a
denial of service (NULL pointer dereference and daemon crash) via
an out-of-sequence DTLS handshake message, related to a fragment
bug. (CVE-2009-1387)
The NSS library library before 3.12.3, as used in Firefox; GnuTLS
before 2.6.4 and 2.7.4; OpenSSL 0.9.8 through 0.9.8k; and other
products support MD2 with X.509 certificates, which might allow
remote attackers to spooof certificates by using MD2 design flaws
to generate a hash collision in less than brute-force time. NOTE:
the scope of this issue is currently limited because the amount of
computation required is still large (CVE-2009-2409).
This update provides a solution to these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:238");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1379", "CVE-2009-1386", "CVE-2009-1387", "CVE-2009-2409");
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

if ( rpm_check( reference:"libopenssl0.9.8-0.9.8g-4.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8g-4.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8g-4.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8g-4.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-0.9.8h-3.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8h-3.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8h-3.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8h-3.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK2008.1")
 || rpm_exists(rpm:"openssl-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2009-1379", value:TRUE);
 set_kb_item(name:"CVE-2009-1386", value:TRUE);
 set_kb_item(name:"CVE-2009-1387", value:TRUE);
 set_kb_item(name:"CVE-2009-2409", value:TRUE);
}
exit(0, "Host is not affected");

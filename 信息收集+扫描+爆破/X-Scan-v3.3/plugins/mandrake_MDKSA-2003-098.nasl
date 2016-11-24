
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14080);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2003:098: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:098 (openssl).");
 script_set_attribute(attribute: "description", value: "Two bugs were discovered in OpenSSL 0.9.6 and 0.9.7 by NISCC. The
parsing of unusual ASN.1 tag values can cause OpenSSL to crash, which
could be triggered by a remote attacker by sending a carefully-crafted
SSL client certificate to an application. Depending upon the
application targetted, the effects seen will vary; in some cases a DoS
(Denial of Service) could be performed, in others nothing noticeable
or adverse may happen. These two vulnerabilities have been assigned
CVE-2003-0543 and CVE-2003-0544.
Additionally, NISCC discovered a third bug in OpenSSL 0.9.7. Certain
ASN.1 encodings that are rejected as invalid by the parser can trigger
a bug in deallocation of a structure, leading to a double free. This
can be triggered by a remote attacker by sending a carefully-crafted
SSL client certificate to an application. This vulnerability may be
exploitable to execute arbitrary code. This vulnerability has been
assigned CVE-2003-0545.
The packages provided have been built with patches provided by the
OpenSSL group that resolve these issues.
A number of server applications such as OpenSSH and Apache that make
use of OpenSSL need to be restarted after the update has been applied
to ensure that they are protected from these issues. Users are
encouraged to restart all of these services or reboot their systems.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:098");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
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

if ( rpm_check( reference:"libopenssl0-0.9.6i-1.5.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.5.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-static-devel-0.9.6i-1.5.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.5.82mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.6.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.6.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-static-devel-0.9.6i-1.6.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.6.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7a-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7a-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7a-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7a-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-0.9.7b-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-devel-0.9.7b-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.7-static-devel-0.9.7b-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.7b-4.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK8.2")
 || rpm_exists(rpm:"openssl-", release:"MDK9.0")
 || rpm_exists(rpm:"openssl-", release:"MDK9.1")
 || rpm_exists(rpm:"openssl-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0543", value:TRUE);
 set_kb_item(name:"CVE-2003-0544", value:TRUE);
 set_kb_item(name:"CVE-2003-0545", value:TRUE);
}
exit(0, "Host is not affected");

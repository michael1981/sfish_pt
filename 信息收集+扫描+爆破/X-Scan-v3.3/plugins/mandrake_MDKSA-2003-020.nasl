
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14005);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:020: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:020 (openssl).");
 script_set_attribute(attribute: "description", value: "In an upcoming paper, Brice Canvel (EPFL), Alain Hiltgen (UBS), Serge
Vaudenay (EPFL), and Martin Vuagnoux (EPFL, Ilion) describe and
demonstrate a timing-based attack on CBC ciphersuites in SSL and TLS.
New versions of openssl have been released in response to this
vulnerability (0.9.6i and 0.9.7a). The openssl released with
Linux-Mandrake 7.2 and Single Network Firewall 7.2 has been patched to
correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:020");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0078");
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

if ( rpm_check( reference:"openssl-0.9.5a-9.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.5a-9.4mdk", release:"MDK7.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.6i-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-static-devel-0.9.6i-1.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-static-devel-0.9.6i-1.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-0.9.6i-1.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-devel-0.9.6i-1.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0-static-devel-0.9.6i-1.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.6i-1.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK7.2")
 || rpm_exists(rpm:"openssl-", release:"MDK8.0")
 || rpm_exists(rpm:"openssl-", release:"MDK8.1")
 || rpm_exists(rpm:"openssl-", release:"MDK8.2")
 || rpm_exists(rpm:"openssl-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0078", value:TRUE);
}
exit(0, "Host is not affected");

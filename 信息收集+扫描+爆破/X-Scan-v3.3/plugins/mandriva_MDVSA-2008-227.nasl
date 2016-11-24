
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36960);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:227-1: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:227-1 (gnutls).");
 script_set_attribute(attribute: "description", value: "Martin von Gagern found a flow in how GnuTLS versions 1.2.4 up until
2.6.1 verified certificate chains provided by a server. A malicious
server could use this flaw to spoof its identity by tricking client
applications that used the GnuTLS library to trust invalid certificates
(CVE-2008-4989).
Update:
It was found that the previously-published patch to correct this
issue caused a regression when dealing with self-signed certificates.
An updated patch that fixes the security issue and resolves the
regression issue has been applied to these packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:227-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-4989");
script_summary(english: "Check for the version of the gnutls package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnutls-2.0.0-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls13-2.0.0-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.0.0-2.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-2.3.0-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls26-2.3.0-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.3.0-2.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-2.4.1-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls26-2.4.1-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.4.1-2.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gnutls-", release:"MDK2008.0")
 || rpm_exists(rpm:"gnutls-", release:"MDK2008.1")
 || rpm_exists(rpm:"gnutls-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-4989", value:TRUE);
}
exit(0, "Host is not affected");

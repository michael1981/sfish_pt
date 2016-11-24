
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37882);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:107: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:107 (openssl).");
 script_set_attribute(attribute: "description", value: "Testing using the Codenomicon TLS test suite discovered a flaw in
the handling of server name extension data in OpenSSL 0.9.8f and
OpenSSL 0.9.8g. If OpenSSL has been compiled using the non-default
TLS server name extensions, a remote attacker could send a carefully
crafted packet to a server application using OpenSSL and cause a
crash. (CVE-2008-0891)
Testing using the Codenomicon TLS test suite discovered a flaw if
the 'Server Key exchange message' is omitted from a TLS handshake
in OpenSSL 0.9.8f and OpenSSL 0.9.8g. If a client connects to a
malicious server with particular cipher suites, the server could
cause the client to crash. (CVE-2008-1672)
The updated packages have been patched to fix these flaws.
Note that any applications using this library must be restarted for
the update to take effect.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:107");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-0891", "CVE-2008-1672");
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

if ( rpm_check( reference:"libopenssl0.9.8-0.9.8g-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-devel-0.9.8g-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libopenssl0.9.8-static-devel-0.9.8g-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-0.9.8g-4.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openssl-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-0891", value:TRUE);
 set_kb_item(name:"CVE-2008-1672", value:TRUE);
}
exit(0, "Host is not affected");


#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38815);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:116: gnutls");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:116 (gnutls).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in gnutls:
lib/pk-libgcrypt.c in libgnutls in GnuTLS before 2.6.6 does not
properly handle invalid DSA signatures, which allows remote attackers
to cause a denial of service (application crash) and possibly have
unspecified other impact via a malformed DSA key that triggers a (1)
free of an uninitialized pointer or (2) double free (CVE-2009-1415).
lib/gnutls_pk.c in libgnutls in GnuTLS 2.5.0 through 2.6.5 generates
RSA keys stored in DSA structures, instead of the intended DSA keys,
which might allow remote attackers to spoof signatures on certificates
or have unspecified other impact by leveraging an invalid DSA key
(CVE-2009-1416).
gnutls-cli in GnuTLS before 2.6.6 does not verify the activation
and expiration times of X.509 certificates, which allows remote
attackers to successfully present a certificate that is (1) not yet
valid or (2) no longer valid, related to lack of time checks in the
_gnutls_x509_verify_certificate function in lib/x509/verify.c in
libgnutls_x509, as used by (a) Exim, (b) OpenLDAP, and (c) libsoup
(CVE-2009-1417).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:116");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2009-1415", "CVE-2009-1416", "CVE-2009-1417");
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

if ( rpm_check( reference:"gnutls-2.3.0-2.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls26-2.3.0-2.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.3.0-2.5mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-2.4.1-2.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls26-2.4.1-2.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.4.1-2.4mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gnutls-2.6.4-1.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls26-2.6.4-1.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libgnutls-devel-2.6.4-1.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gnutls-", release:"MDK2008.1")
 || rpm_exists(rpm:"gnutls-", release:"MDK2009.0")
 || rpm_exists(rpm:"gnutls-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2009-1415", value:TRUE);
 set_kb_item(name:"CVE-2009-1416", value:TRUE);
 set_kb_item(name:"CVE-2009-1417", value:TRUE);
}
exit(0, "Host is not affected");

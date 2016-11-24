
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2006-979
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(24182);
 script_version ("$Revision: 1.5 $");
script_name(english: "Fedora 5 2006-979: nss");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2006-979 (nss)");
 script_set_attribute(attribute: "description", value: "Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

Update Information:

Network Security Services (NSS) is a set of libraries
designed to support cross-platform development of
security-enabled client and server applications.
Applications built with NSS can support SSL v2 and v3, TLS,
PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509 v3
certificates, and other security standards.

Daniel Bleichenbacher recently described an implementation
error in RSA signature verification. For RSA keys with
exponent 3 it is possible for an attacker to forge a
signature that which would be incorrectly verified by the
NSS library. (CVE-2006-4340)

All users of NSS, which includes users of Firefox,
Thunderbird, Seamonkey, and other mozilla.org products, are
recommended to update to this package, which contains NSS
version 3.11.3 which is not vulnerable to this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2006-4340");
script_summary(english: "Check for the version of the nss package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"nss-3.11.3-0.5.fc5", release:"FC5") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

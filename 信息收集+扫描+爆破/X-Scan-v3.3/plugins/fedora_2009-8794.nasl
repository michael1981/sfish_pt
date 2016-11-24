
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-8794
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40677);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 10 2009-8794: neon");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-8794 (neon)");
 script_set_attribute(attribute: "description", value: "neon is an HTTP and WebDAV client library, with a C interface;
providing a high-level interface to HTTP and WebDAV methods along
with a low-level interface for HTTP request handling.  neon
supports persistent connections, proxy servers, basic, digest and
Kerberos authentication, and has complete SSL support.

-
Update Information:

This update includes the latest release of neon, version 0.28.6.    This fixes
two security issues:    * the 'billion laughs' attack against expat could allow
a Denial of Service attack by a malicious server.  (CVE-2009-2473)    * an
embedded NUL byte in a certificate subject name could allow an undetected MITM
attack against an SSL server if a trusted CA issues such a cert.     Several bu
g
fixes are also included, notably:    * X.509v1 CA certificates are trusted by
default  * Fix handling of some PKCS#12 certificates
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-2473");
script_summary(english: "Check for the version of the neon package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"neon-0.28.6-1.fc10", release:"FC10") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");

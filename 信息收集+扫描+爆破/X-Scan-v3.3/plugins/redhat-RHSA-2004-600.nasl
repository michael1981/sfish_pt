
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(15960);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2004-600: apache");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-600");
 script_set_attribute(attribute: "description", value: '
  Updated apache and mod_ssl packages that fix various minor security issues
  and bugs in the Apache Web server are now available for Red Hat Enterprise
  Linux 2.1.

  The Apache HTTP Server is a powerful, full-featured, efficient, and
  freely-available Web server. The mod_ssl module provides strong
  cryptography for the Apache Web server via the Secure Sockets Layer (SSL)
  and Transport Layer Security (TLS) protocols.

  A buffer overflow was discovered in the mod_include module. This flaw
  could allow a local user who is authorized to create server-side include
  (SSI) files to gain the privileges of a httpd child (user \'apache\'). The
  Common Vulnerabilities and Exposures project (cve.mitre.org) has assigned
  the name CAN-2004-0940 to this issue.

  The mod_digest module does not properly verify the nonce of a client
  response by using a AuthNonce secret. This could allow a malicious user who
  is able to sniff network traffic to conduct a replay attack against a
  website using Digest protection. Note that mod_digest implements an older
  version of the MD5 Digest Authentication specification, which is known not
  to work with modern browsers. This issue does not affect mod_auth_digest.
  (CAN-2003-0987).

  An issue has been discovered in the mod_ssl module when configured to use
  the "SSLCipherSuite" directive in a directory or location context. If a
  particular location context has been configured to require a specific set
  of cipher suites, then a client is able to access that location using
  any cipher suite allowed by the virtual host configuration.
  (CAN-2004-0885).

  Several bugs in mod_ssl were also discovered, including:

  - memory leaks in SSL variable handling

  - possible crashes in the dbm and shmht session caches

  Red Hat Enterprise Linux 2.1 users of the Apache HTTP Server should upgrade
  to these erratum packages, which contains Apache version 1.3.27 with
  backported patches correcting these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-600.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0987", "CVE-2004-0885", "CVE-2004-0940");
script_summary(english: "Check for the version of the apache packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"apache-1.3.27-9.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-devel-1.3.27-9.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"apache-manual-1.3.27-9.ent", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mod_ssl-2.8.12-7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

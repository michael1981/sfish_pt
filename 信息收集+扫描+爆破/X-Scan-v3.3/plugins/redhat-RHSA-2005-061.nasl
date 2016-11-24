
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(16384);
 script_version ("$Revision: 1.6 $");
 script_name(english: "RHSA-2005-061: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-061");
 script_set_attribute(attribute: "description", value: '
  An updated Squid package that fixes several security issues is now
  available.

  Squid is a full-featured Web proxy cache.

  A buffer overflow flaw was found in the Gopher relay parser. This bug
  could allow a remote Gopher server to crash the Squid proxy that reads data
  from it. Although Gopher servers are now quite rare, a malicious web page
  (for example) could redirect or contain a frame pointing to an attacker\'s
  malicious gopher server. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0094 to this issue.

  An integer overflow flaw was found in the WCCP message parser. It is
  possible to crash the Squid server if an attacker is able to send a
  malformed WCCP message with a spoofed source address matching Squid\'s
  "home router". The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0095 to this issue.

  A memory leak was found in the NTLM fakeauth_auth helper. It is possible
  that an attacker could place the Squid server under high load, causing the
  NTML fakeauth_auth helper to consume a large amount of memory, resulting in
  a denial of service. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2005-0096 to this issue.

  A NULL pointer de-reference bug was found in the NTLM fakeauth_auth helper.
  It is possible for an attacker to send a malformed NTLM type 3 message,
  causing the Squid server to crash. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0097 to
  this issue.

  A username validation bug was found in squid_ldap_auth. It is possible for
  a username to be padded with spaces, which could allow a user to bypass
  explicit access control rules or confuse accounting. The Common
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name
  CAN-2005-0173 to this issue.

  The way Squid handles HTTP responses was found to need strengthening. It is
  possible that a malicious web server could send a series of HTTP responses
  in such a way that the Squid cache could be poisoned, presenting users with
  incorrect webpages. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the names CAN-2005-0174 and CAN-2005-0175 to
  these issues.

  A bug was found in the way Squid handled oversized HTTP response headers.
  It is possible that a malicious web server could send a specially crafted
  HTTP header which could cause the Squid cache to be poisoned, presenting
  users with incorrect webpages. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2005-0241 to this issue.

  A buffer overflow bug was found in the WCCP message parser. It is possible
  that an attacker could send a malformed WCCP message which could crash the
  Squid server or execute arbitrary code. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CAN-2005-0211
  to this issue.

  Users of Squid should upgrade to this updated package, which contains
  backported patches, and is not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-061.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-0094", "CVE-2005-0095", "CVE-2005-0096", "CVE-2005-0097", "CVE-2005-0173", "CVE-2005-0174", "CVE-2005-0175", "CVE-2005-0211", "CVE-2005-0241");
script_summary(english: "Check for the version of the squid packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.4.STABLE7-1.21as.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-6.3E.7", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");

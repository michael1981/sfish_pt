
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27052);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0964: openssl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0964");
 script_set_attribute(attribute: "description", value: '
  Updated OpenSSL packages that correct several security issues are now
  available for Red Hat Enterprise 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  OpenSSL is a toolkit that implements Secure Sockets Layer (SSL v2/v3) and
  Transport Layer Security (TLS v1) protocols as well as a full-strength
  general purpose cryptography library. Datagram TLS (DTLS) is a protocol
  based on TLS that is capable of securing datagram transport (UDP for
  instance).

  The OpenSSL security team discovered a flaw in DTLS support. An attacker
  could create a malicious client or server that could trigger a heap
  overflow. This is possibly exploitable to run arbitrary code, but it has
  not been verified (CVE-2007-4995). Note that this flaw only affects
  applications making use of DTLS. Red Hat does not ship any DTLS client or
  server applications in Red Hat Enterprise Linux.

  A flaw was found in the SSL_get_shared_ciphers() utility function. An
  attacker could send a list of ciphers to an application that used this
  function and overrun a buffer with a single byte (CVE-2007-5135). Few
  applications make use of this vulnerable function and generally it is used
  only when applications are compiled for debugging.

  A number of possible side-channel attacks were discovered affecting
  OpenSSL. A local attacker could possibly obtain RSA private keys being
  used on a system. In practice these attacks would be difficult to perform
  outside of a lab environment. This update contains backported patches
  designed to mitigate these issues. (CVE-2007-3108).

  Users of OpenSSL should upgrade to these updated packages, which contain
  backported patches to resolve these issues.

  Please note that the fix for the DTLS flaw involved an overhaul of the DTLS
  handshake processing which may introduce incompatibilities if a new client
  is used with an older server.

  After installing this update, users are advised to either restart all
  services that use OpenSSL or restart their system.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0964.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-3108", "CVE-2007-4995", "CVE-2007-5135");
script_summary(english: "Check for the version of the openssl packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openssl-0.9.8b-8.3.el5_0.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-devel-0.9.8b-8.3.el5_0.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssl-perl-0.9.8b-8.3.el5_0.2", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
